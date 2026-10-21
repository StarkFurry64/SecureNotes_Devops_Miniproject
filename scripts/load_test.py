"""Small load generator for the live demo: makes the Azure dashboard graphs move.

It mixes three kinds of traffic so every dashboard tile shows something:
  ~75% GET /            page views (request rate, response time)
  ~15% POST /add        real notes, with the CSRF token (the "notes created" metric)
  ~10% GET /no-such-page  404s (the "failed requests" tile)

Usage:
  python scripts/load_test.py --url https://<your-app>.azurecontainerapps.io --duration 60 --workers 5
"""

import argparse
import random
import re
import sys
import threading
import time
from collections import Counter

import requests

CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


def worker(base_url, deadline, stats, lock, seed):
    rng = random.Random(seed)
    session = requests.Session()
    token = None
    while time.monotonic() < deadline:
        roll = rng.random()
        try:
            if roll < 0.15 and token:
                response = session.post(f"{base_url}/add", data={"text": f"load test note {rng.randint(1, 9999)}",
                                                                 "csrf_token": token}, timeout=10)
                kind = "add note"
            elif roll < 0.25:
                response = session.get(f"{base_url}/no-such-page", timeout=10)
                kind = "404 page"
            else:
                response = session.get(f"{base_url}/", timeout=10)
                kind = "home page"
                match = CSRF_FIELD.search(response.text)
                if match:
                    token = match.group(1)
            outcome = f"{kind} -> {response.status_code}"
        except requests.exceptions.RequestException as exc:
            outcome = f"error -> {exc.__class__.__name__}"
        with lock:
            stats[outcome] += 1


def run(base_url, duration, workers):
    base_url = base_url.rstrip("/")
    stats, lock = Counter(), threading.Lock()
    deadline = time.monotonic() + duration
    threads = [threading.Thread(target=worker, args=(base_url, deadline, stats, lock, i), daemon=True)
               for i in range(workers)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    total = sum(stats.values())
    print(f"Sent {total} requests in {elapsed:.0f}s ({total / max(elapsed, 0.001):.1f} req/s) to {base_url}")
    for outcome, count in sorted(stats.items()):
        print(f"  {outcome:<24} {count}")
    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(description="SecureNotes demo load generator")
    parser.add_argument("--url", required=True, help="base URL of the app, e.g. https://securenotes....io")
    parser.add_argument("--duration", type=int, default=60, help="seconds to run (default 60)")
    parser.add_argument("--workers", type=int, default=5, help="parallel users (default 5)")
    args = parser.parse_args(argv)
    stats = run(args.url, args.duration, args.workers)
    return 0 if stats else 1


if __name__ == "__main__":
    sys.exit(main())
