"""Automated health monitor for the SecureNotes /health endpoint.

Each check runs four tests:
  1. connectivity   - can we reach the API at all (connection refused / timeout)?
  2. HTTP status    - is the status code 200?
  3. response time  - below --warn-ms is HEALTHY, below --fail-ms is WARNING, above is UNHEALTHY
  4. response body  - does the JSON say {"status": "healthy"}?

Results are appended to a CSV history file, from which availability and average
response time are calculated. When the service goes down (or comes back) an alert
is posted to ALERT_WEBHOOK_URL (Discord or Slack incoming webhook), if one is set.

Usage:
  python monitor/health_check.py --url http://localhost:5000/health            # one check
  python monitor/health_check.py --url ... --interval 10                       # check every 10 s
  python monitor/health_check.py --report                                      # availability report

Exit code: 0 when the last check was HEALTHY or WARNING, 1 when it was UNHEALTHY.
"""

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

HEALTHY = "HEALTHY"
WARNING = "WARNING"
UNHEALTHY = "UNHEALTHY"

HISTORY_FIELDS = ["timestamp", "url", "result", "status_code", "response_ms", "detail"]
DEFAULT_HISTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.csv")


@dataclass
class CheckResult:
    url: str
    result: str
    status_code: int | None = None
    response_ms: float | None = None
    detail: str = ""
    checks: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @property
    def ok(self):
        return self.result != UNHEALTHY


def check_health(url, timeout=5.0, warn_ms=500, fail_ms=1000, expected_status="healthy", session=None):
    """Run the four checks against url and return a CheckResult."""
    http = session or requests
    checks = {}

    # Check 1: connectivity
    started = time.perf_counter()
    try:
        response = http.get(url, timeout=timeout)
    except requests.exceptions.Timeout:
        checks["connectivity"] = "FAIL"
        return CheckResult(url, UNHEALTHY, detail=f"Timeout after {timeout:g}s", checks=checks)
    except requests.exceptions.RequestException as exc:
        checks["connectivity"] = "FAIL"
        return CheckResult(url, UNHEALTHY, detail=f"Connection failed: {exc.__class__.__name__}", checks=checks)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    checks["connectivity"] = "PASS"

    problems = []
    result = HEALTHY

    # Check 2: HTTP status
    if response.status_code == 200:
        checks["http_status"] = "PASS"
    else:
        checks["http_status"] = "FAIL"
        problems.append(f"HTTP {response.status_code}")
        result = UNHEALTHY

    # Check 3: response time
    if elapsed_ms > fail_ms:
        checks["response_time"] = "FAIL"
        problems.append(f"slow response {elapsed_ms:.0f} ms > {fail_ms} ms")
        result = UNHEALTHY
    elif elapsed_ms > warn_ms:
        checks["response_time"] = "WARN"
        problems.append(f"slow response {elapsed_ms:.0f} ms > {warn_ms} ms")
        if result == HEALTHY:
            result = WARNING
    else:
        checks["response_time"] = "PASS"

    # Check 4: response content
    try:
        body = response.json()
        reported = body.get("status") if isinstance(body, dict) else None
    except ValueError:
        reported = None
    if reported == expected_status:
        checks["response_body"] = "PASS"
    else:
        checks["response_body"] = "FAIL"
        problems.append(f"body status {reported!r}, expected {expected_status!r}")
        result = UNHEALTHY

    return CheckResult(
        url,
        result,
        status_code=response.status_code,
        response_ms=elapsed_ms,
        detail="; ".join(problems) or "all checks passed",
        checks=checks,
    )


def append_history(result, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=HISTORY_FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow({
            "timestamp": result.timestamp,
            "url": result.url,
            "result": result.result,
            "status_code": result.status_code if result.status_code is not None else "",
            "response_ms": result.response_ms if result.response_ms is not None else "",
            "detail": result.detail,
        })


def load_history(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def summarise(rows):
    """Availability = share of checks that were not UNHEALTHY."""
    total = len(rows)
    up = sum(1 for row in rows if row["result"] != UNHEALTHY)
    times = [float(row["response_ms"]) for row in rows if row.get("response_ms")]
    return {
        "total_checks": total,
        "successful": up,
        "failed": total - up,
        "availability_pct": round(100.0 * up / total, 2) if total else 0.0,
        "avg_response_ms": round(sum(times) / len(times), 1) if times else None,
    }


def format_result(result):
    lines = [
        "API Health Check",
        "----------------",
        f"Time          : {result.timestamp}",
        f"URL           : {result.url}",
    ]
    if result.status_code is None:
        lines.append("Connection    : FAILED")
    else:
        lines.append(f"Status Code   : {result.status_code}")
        lines.append(f"Response Time : {result.response_ms:.0f} ms")
    for name, verdict in result.checks.items():
        lines.append(f"  {name:<13}: {verdict}")
    lines.append(f"Detail        : {result.detail}")
    lines.append(f"Result        : {result.result}")
    return "\n".join(lines)


def format_report(stats):
    avg = f"{stats['avg_response_ms']} ms" if stats["avg_response_ms"] is not None else "n/a"
    return "\n".join([
        f"Total checks     : {stats['total_checks']}",
        f"Successful       : {stats['successful']}",
        f"Failed           : {stats['failed']}",
        f"Availability     : {stats['availability_pct']}%",
        f"Average response : {avg}",
    ])


def send_alert(webhook_url, result, recovered=False, session=None):
    """Post an alert to a Discord or Slack incoming webhook. Returns True on success."""
    if not webhook_url:
        return False
    title = "API Health RECOVERED" if recovered else "API Health ALERT"
    message = (
        f"**{title}**\n"
        f"Service: SecureNotes\n"
        f"Status: {result.result}\n"
        f"Endpoint: {result.url}\n"
        f"Detail: {result.detail}\n"
        f"Time: {result.timestamp}"
    )
    http = session or requests
    try:
        # "content" is read by Discord, "text" by Slack.
        response = http.post(webhook_url, json={"content": message, "text": message}, timeout=10)
        return response.status_code < 300
    except requests.exceptions.RequestException as exc:
        print(f"Alert could not be delivered: {exc}", file=sys.stderr)
        return False


def write_github_summary(result, stats):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    icon = {"HEALTHY": "✅", "WARNING": "⚠️", "UNHEALTHY": "❌"}[result.result]
    rows = "\n".join(f"| {name} | {verdict} |" for name, verdict in result.checks.items())
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(
            f"## {icon} SecureNotes health: {result.result}\n\n"
            f"- URL: `{result.url}`\n- Detail: {result.detail}\n"
            f"- Response time: {result.response_ms if result.response_ms is not None else 'n/a'} ms\n\n"
            f"| Check | Verdict |\n|---|---|\n{rows}\n\n"
            f"**History:** {stats['total_checks']} checks, availability {stats['availability_pct']}%, "
            f"average {stats['avg_response_ms']} ms\n"
        )


def run_once(args, previous_ok=None):
    result = check_health(args.url, args.timeout, args.warn_ms, args.fail_ms, args.expect_status)
    # Retry before declaring the service down, to ride out a single dropped request.
    attempt = 1
    while not result.ok and attempt <= args.retries:
        time.sleep(args.retry_delay)
        attempt += 1
        result = check_health(args.url, args.timeout, args.warn_ms, args.fail_ms, args.expect_status)

    append_history(result, args.history)
    stats = summarise(load_history(args.history))

    if args.json:
        print(json.dumps({**result.__dict__, "history": stats}))
    else:
        print(format_result(result))
        print()

    # Alert on a state change: always when going down, and on recovery after a failure.
    if previous_ok is None:
        if not result.ok:
            send_alert(args.webhook, result)
    elif previous_ok and not result.ok:
        send_alert(args.webhook, result)
    elif not previous_ok and result.ok:
        send_alert(args.webhook, result, recovered=True)

    write_github_summary(result, stats)
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="SecureNotes API health monitor")
    parser.add_argument("--url", default=os.environ.get("MONITOR_URL", "http://localhost:5000/health"))
    parser.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    parser.add_argument("--warn-ms", type=int, default=500, help="response time that raises a WARNING")
    parser.add_argument("--fail-ms", type=int, default=1000, help="response time that counts as UNHEALTHY")
    parser.add_argument("--expect-status", default="healthy", help="expected value of the JSON 'status' field")
    parser.add_argument("--retries", type=int, default=2, help="extra attempts before declaring UNHEALTHY")
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--interval", type=float, default=0, help="seconds between checks; 0 runs one check")
    parser.add_argument("--count", type=int, default=0, help="stop after N checks in interval mode (0 = forever)")
    parser.add_argument("--history", default=os.environ.get("MONITOR_HISTORY", DEFAULT_HISTORY))
    parser.add_argument("--webhook", default=os.environ.get("ALERT_WEBHOOK_URL", ""))
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument("--report", action="store_true", help="print availability from history and exit")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.report:
        print(format_report(summarise(load_history(args.history))))
        return 0

    if args.interval <= 0:
        return 0 if run_once(args).ok else 1

    print(f"Monitoring {args.url} every {args.interval:g}s (Ctrl+C to stop)\n", flush=True)
    previous_ok, checks_done, result = None, 0, None
    try:
        while True:
            result = run_once(args, previous_ok)
            sys.stdout.flush()
            previous_ok = result.ok
            checks_done += 1
            if args.count and checks_done >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    print(format_report(summarise(load_history(args.history))))
    return 0 if result is None or result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
