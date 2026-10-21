"""AI remediation agent (Stage 4 of the pipeline).

When a security gate fails, this agent:
  1. collects findings   - SonarCloud issues and hotspots (API), the local secret scan,
                           and the Trivy JSON report uploaded by Stage 2;
  2. picks a mode        - secret (code findings), image (container findings), or all;
  3. asks the model      - sends findings + the affected files to NVIDIA NIM
                           (Nemotron 70B) and receives full replacement files plus a
                           plain-language explanation as JSON;
  4. validates the patch - only allow-listed files may change, Python must compile,
                           the Dockerfile must keep a FROM line, and the secret scan
                           must come back clean;
  5. opens a pull request on a new branch.

The agent never merges, never pushes to the base branch and cannot approve its own
pull request: a developer reviews every change. If the model is unavailable or its
answer fails validation, a small deterministic rule-based fixer is used instead and
the pull request says so.

Usage (see `--help`):
  python scripts/remediate_agent.py --mode auto --trivy-report trivy-results.json --dry-run
"""

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_scan import scan_paths, scan_text  # noqa: E402

NIM_URL = os.environ.get("NVIDIA_NIM_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
DEFAULT_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"
SONAR_URL = os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io")
DEFAULT_SONAR_KEY = "StarkFurry64_SecureNotes_Devops_Miniproject2"

# The only files the agent may modify. Workflows, scripts and tests are deliberately
# excluded so that a manipulated model response cannot weaken the pipeline itself.
ALLOWED_FILES = {"app.py", "Dockerfile", "requirements.txt"}
MODE_FILES = {"secret": ["app.py"], "image": ["Dockerfile"], "all": ["app.py", "Dockerfile"]}
RECOMMENDED_BASE_IMAGE = "python:3.12-slim"
PR_TITLE_PREFIX = "[AI Remediation]"

SYSTEM_PROMPT = f"""You are a security remediation assistant inside a CI/CD pipeline.
You receive security findings and the full contents of the affected files of a small
Flask application. Produce the smallest safe change that resolves the findings.

Rules:
- Never hardcode credentials. Read them with os.environ.get("APP_SECRET_KEY", "default-dev-key")
  or a similarly named environment variable.
- Remove duplicated input-validation code by routing it through one function named
  validate_note_input when duplication is reported.
- For container findings use the base image {RECOMMENDED_BASE_IMAGE} and run
  `apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*`.
- Keep behaviour, routes, function names and the /health response unchanged.
- Only modify these files: {", ".join(sorted(ALLOWED_FILES))}.

Respond with ONLY a JSON object, no markdown fences, of the form:
{{"explanation": "<plain-language summary for the reviewer>",
  "files": [{{"path": "<file>", "content": "<complete new file content>"}}]}}"""


# --------------------------------------------------------------------------- findings

def load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def trivy_findings(report):
    """Flatten a Trivy JSON report into finding dicts."""
    findings = []
    for result in (report or {}).get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "source": "trivy",
                "rule": vuln.get("VulnerabilityID", "?"),
                "file": "Dockerfile",
                "line": None,
                "severity": vuln.get("Severity", "UNKNOWN"),
                "message": (
                    f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} "
                    f"(fixed in {vuln.get('FixedVersion') or 'n/a'}) in {result.get('Target')}"
                ),
            })
    return findings


def sonar_findings(project_key, token, session=None):
    """Fetch open issues and security hotspots from SonarCloud."""
    if not token:
        return []
    http = session or requests
    headers = {"Authorization": f"Bearer {token}"}
    findings = []

    def _file(component):
        return component.split(":", 1)[1] if ":" in component else component

    try:
        issues = http.get(
            f"{SONAR_URL}/api/issues/search",
            params={"componentKeys": project_key, "resolved": "false", "ps": 100},
            headers=headers, timeout=30,
        )
        issues.raise_for_status()
        for issue in issues.json().get("issues", []):
            findings.append({
                "source": "sonarcloud",
                "rule": issue.get("rule"),
                "file": _file(issue.get("component", "")),
                "line": issue.get("line"),
                "severity": issue.get("severity", "UNKNOWN"),
                "message": issue.get("message", ""),
            })
        hotspots = http.get(
            f"{SONAR_URL}/api/hotspots/search",
            params={"projectKey": project_key, "status": "TO_REVIEW", "ps": 100},
            headers=headers, timeout=30,
        )
        hotspots.raise_for_status()
        for hotspot in hotspots.json().get("hotspots", []):
            findings.append({
                "source": "sonarcloud",
                "rule": hotspot.get("ruleKey"),
                "file": _file(hotspot.get("component", "")),
                "line": hotspot.get("line"),
                "severity": hotspot.get("vulnerabilityProbability", "HIGH"),
                "message": hotspot.get("message", ""),
            })
    except (requests.exceptions.RequestException, ValueError) as exc:
        print(f"[agent] SonarCloud findings unavailable: {exc}")
    return findings


def collect_findings(args):
    findings = []
    findings += sonar_findings(args.sonar_project_key, os.environ.get("SONAR_TOKEN", ""))
    for finding in scan_paths([os.path.join(args.repo_root, "app.py")]):
        finding["file"] = "app.py"
        findings.append(finding)
    findings += load_json(args.secret_report) or []
    findings += trivy_findings(load_json(args.trivy_report))

    # De-duplicate: the same secret can arrive from the live scan and the saved Stage 1 report.
    unique, seen = [], set()
    for finding in findings:
        key = (finding["source"], finding["rule"], finding.get("file"), finding.get("line"))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def resolve_mode(requested, findings):
    """auto -> secret / image / all depending on which gates produced findings."""
    if requested != "auto":
        return requested
    code = any(f["source"] != "trivy" for f in findings)
    image = any(f["source"] == "trivy" for f in findings)
    if code and image:
        return "all"
    if code:
        return "secret"
    if image:
        return "image"
    return None


def relevant_findings(mode, findings):
    """Keep only findings the agent can act on: the right gate, in a file this mode may change."""
    files = set(MODE_FILES[mode])
    kinds = {"secret": {"code"}, "image": {"image"}, "all": {"code", "image"}}[mode]
    return [f for f in findings
            if ("image" if f["source"] == "trivy" else "code") in kinds and f.get("file") in files]


# --------------------------------------------------------------------------- patching

def read_files(repo_root, names):
    files = {}
    for name in names:
        path = os.path.join(repo_root, name)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                files[name] = handle.read()
    return files


def build_user_prompt(findings, files):
    shown = findings[:40]
    lines = [f"- [{f['source']}] {f['rule']} {f['severity']} {f['file']}:{f.get('line') or '-'} {f['message']}"
             for f in shown]
    if len(findings) > len(shown):
        lines.append(f"- ... and {len(findings) - len(shown)} more findings of the same kinds")
    parts = ["Security findings:", *lines, ""]
    for name, content in files.items():
        parts += [f"=== FILE: {name} ===", content, f"=== END FILE: {name} ===", ""]
    return "\n".join(parts)


def extract_json(text):
    """Pull the JSON object out of a model reply, tolerating markdown fences and chatter."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.M)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in model reply")
    return json.loads(text[start:end + 1])


def call_nim(findings, files, model, api_key, session=None):
    http = session or requests
    response = http.post(
        NIM_URL,
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(findings, files)},
            ],
            "temperature": 0.2,
            "top_p": 0.7,
            "max_tokens": 4096,
        },
        timeout=180,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    proposal = extract_json(content)
    return {
        "explanation": str(proposal.get("explanation", "")).strip(),
        "files": {item["path"]: item["content"] for item in proposal.get("files", [])
                  if isinstance(item, dict) and "path" in item and "content" in item},
    }


def rule_based_fix(mode, files):
    """Deterministic fallback used when the model is unavailable or its patch is rejected."""
    patched, notes = {}, []

    if mode in ("secret", "all") and "app.py" in files:
        source = files["app.py"]
        new = re.sub(
            r"""app\.config\[\s*["']SECRET_KEY["']\s*\]\s*=\s*["'][^"']*["']""",
            'app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "default-dev-key")',
            source,
        )

        def _env(match):
            name = match.group("name")
            return f'{match.group("indent")}{name} = os.environ.get("{name.upper()}", "")'

        new = re.sub(
            r"""^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY)[A-Za-z_]*)\s*=\s*["'][^"']+["']""",
            _env, new, flags=re.M | re.I,
        )
        if new != source:
            if not re.search(r"^import os\b", new, flags=re.M):
                new = "import os\n" + new
            patched["app.py"] = new
            notes.append("Replaced hardcoded secrets in app.py with environment variable lookups.")

    if mode in ("image", "all") and "Dockerfile" in files:
        source = files["Dockerfile"]
        new = re.sub(r"^FROM\s+\S+", f"FROM {RECOMMENDED_BASE_IMAGE}", source, count=1, flags=re.M)
        if "apt-get upgrade" not in new:
            new = re.sub(
                r"^(WORKDIR .*)$",
                r"\1\n\nRUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*",
                new, count=1, flags=re.M,
            )
        if new != source:
            patched["Dockerfile"] = new
            notes.append(f"Moved the base image to {RECOMMENDED_BASE_IMAGE} and applied Debian security updates.")

    return {"explanation": " ".join(notes), "files": patched}


def validate_patch(proposal, original, mode):
    """Return a list of problems; an empty list means the patch is acceptable."""
    problems = []
    changed = {path: content for path, content in proposal["files"].items() if original.get(path) != content}
    if not changed:
        problems.append("patch does not change any file")
    for path, content in changed.items():
        if path not in ALLOWED_FILES:
            problems.append(f"{path} is not on the allow-list")
            continue
        if len(content) > 100_000:
            problems.append(f"{path} is implausibly large")
        if path.endswith(".py"):
            try:
                compile(content, path, "exec")
            except SyntaxError as exc:
                problems.append(f"{path} does not compile: {exc}")
            if scan_text(content, path):
                problems.append(f"{path} still contains a hardcoded secret")
            if "/health" not in content:
                problems.append(f"{path} lost the /health endpoint")
        if path == "Dockerfile":
            if not re.search(r"^FROM\s+\S+", content, flags=re.M):
                problems.append("Dockerfile has no FROM line")
            if mode in ("image", "all") and re.search(r"^FROM\s+python:3\.[0-8]\b", content, flags=re.M):
                problems.append("Dockerfile still uses an outdated base image")
    proposal["files"] = changed
    return problems


def generate_patch(args, mode, findings):
    files = read_files(args.repo_root, MODE_FILES[mode])
    api_key = os.environ.get("NVIDIA_API_KEY", "")
    model = os.environ.get("NVIDIA_MODEL") or DEFAULT_MODEL

    if args.provider in ("auto", "nim") and api_key:
        try:
            print(f"[agent] asking {model} via NVIDIA NIM for a patch ...")
            proposal = call_nim(findings, files, model, api_key)
            problems = validate_patch(proposal, files, mode)
            if not problems:
                return proposal, files, f"NVIDIA NIM ({model})"
            print("[agent] model patch rejected: " + "; ".join(problems))
        except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as exc:
            print(f"[agent] model call failed: {exc}")
        if args.provider == "nim":
            return None, files, None
    elif args.provider == "nim":
        print("[agent] NVIDIA_API_KEY is not set")
        return None, files, None

    print("[agent] using the rule-based fallback fixer")
    proposal = rule_based_fix(mode, files)
    problems = validate_patch(proposal, files, mode)
    if problems:
        print("[agent] fallback patch rejected: " + "; ".join(problems))
        return None, files, None
    return proposal, files, "rule-based fallback"


# --------------------------------------------------------------------------- pull request

def render_diff(original, patched):
    chunks = []
    for path, content in patched.items():
        chunks += difflib.unified_diff(
            original.get(path, "").splitlines(keepends=True), content.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        )
    return "".join(chunks)


def build_pr_body(mode, findings, proposal, generator, run_url):
    rows = "\n".join(
        f"| {f['source']} | `{f['rule']}` | {f['severity']} | `{f['file']}`{':' + str(f['line']) if f.get('line') else ''} |"
        for f in findings[:25]
    )
    more = f"\n\n_…and {len(findings) - 25} more._" if len(findings) > 25 else ""
    return f"""## 🤖 AI-proposed security fix ({mode})

> **Human review required.** This pull request was generated automatically after a
> security gate failed. The agent cannot merge, approve or push to the base branch.
> Merging this PR starts a fresh pipeline run that re-checks the fix.

### Explanation
{proposal['explanation'] or '_No explanation provided._'}

### Findings addressed
| Source | Rule | Severity | Location |
|---|---|---|---|
{rows}{more}

### Files changed
{chr(10).join(f'- `{path}`' for path in proposal['files'])}

### Reviewer checklist
- [ ] The change fixes the cause, not only the symptom
- [ ] No behaviour change beyond the fix (routes, `/health` response)
- [ ] Required environment variables (e.g. `APP_SECRET_KEY`) are documented / configured

---
Generated by `scripts/remediate_agent.py` using **{generator}**{f' in [this pipeline run]({run_url})' if run_url else ''}.
"""


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def open_pull_request(args, mode, findings, proposal, generator):
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not repo or not token:
        raise RuntimeError("GITHUB_REPOSITORY and GITHUB_TOKEN are required to open a pull request")

    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    owner = repo.split("/")[0]

    # Do not pile up duplicate PRs while an earlier one is still waiting for review.
    open_prs = requests.get(f"{api}/repos/{repo}/pulls", headers=headers,
                            params={"state": "open", "base": args.base, "per_page": 100}, timeout=30)
    open_prs.raise_for_status()
    for pr in open_prs.json():
        if pr["title"].startswith(f"{PR_TITLE_PREFIX} {mode}"):
            print(f"[agent] an open remediation PR already exists: {pr['html_url']}")
            return pr["html_url"]

    run_id = os.environ.get("GITHUB_RUN_ID", datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    branch = f"ai-remediation/{mode}-{run_id}"
    if branch == args.base:
        raise RuntimeError("refusing to write to the base branch")

    root = args.repo_root
    git("config", "user.name", "securenotes-remediation-bot", cwd=root)
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com", cwd=root)
    git("checkout", "-b", branch, cwd=root)
    for path, content in proposal["files"].items():
        with open(os.path.join(root, path), "w", encoding="utf-8") as handle:
            handle.write(content)
    git("add", *proposal["files"].keys(), cwd=root)
    git("commit", "-m", f"fix(security): AI remediation for {mode} findings\n\n{proposal['explanation']}", cwd=root)
    git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=root)

    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_url = f"{server}/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID") else ""
    response = requests.post(
        f"{api}/repos/{repo}/pulls", headers=headers, timeout=30,
        json={
            "title": f"{PR_TITLE_PREFIX} {mode}: fix {len(findings)} security finding(s)",
            "head": f"{owner}:{branch}",
            "base": args.base,
            "body": build_pr_body(mode, findings, proposal, generator, run_url),
        },
    )
    if response.status_code == 403:
        raise RuntimeError(
            "GitHub refused to create the PR. Enable Settings > Actions > General > "
            "'Allow GitHub Actions to create and approve pull requests'."
        )
    response.raise_for_status()
    return response.json()["html_url"]


def write_step_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")


# --------------------------------------------------------------------------- main

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="SecureNotes AI remediation agent")
    parser.add_argument("--mode", choices=["auto", "secret", "image", "all"], default="auto",
                        help="auto picks secret/image/all from the findings")
    parser.add_argument("--provider", choices=["auto", "nim", "rules"], default="auto",
                        help="auto = NVIDIA NIM with rule-based fallback")
    parser.add_argument("--trivy-report", default="trivy-results.json")
    parser.add_argument("--secret-report", default="secret-findings.json")
    parser.add_argument("--sonar-project-key", default=os.environ.get("SONAR_PROJECT_KEY") or DEFAULT_SONAR_KEY)
    parser.add_argument("--base", default=os.environ.get("BASE_BRANCH", "main"))
    parser.add_argument("--repo-root", default=os.getcwd())
    parser.add_argument("--dry-run", action="store_true", help="print the patch instead of opening a PR")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    findings = collect_findings(args)
    print(f"[agent] collected {len(findings)} finding(s)")

    mode = resolve_mode(args.mode, findings)
    if mode is None:
        print("[agent] no findings to remediate - nothing to do")
        write_step_summary("### 🤖 Remediation agent\nNo findings to remediate.")
        return 0
    scoped = relevant_findings(mode, findings)
    print(f"[agent] mode: {mode} ({len(scoped)} relevant finding(s))")

    proposal, original, generator = generate_patch(args, mode, scoped)
    if proposal is None:
        write_step_summary(f"### 🤖 Remediation agent ({mode})\n❌ No acceptable patch could be produced.")
        return 1

    diff = render_diff(original, proposal["files"])
    print(f"[agent] patch from {generator}:\n{proposal['explanation']}\n\n{diff}")

    if args.dry_run:
        return 0

    url = open_pull_request(args, mode, scoped, proposal, generator)
    print(f"[agent] pull request: {url}")
    write_step_summary(
        f"### 🤖 Remediation agent ({mode})\nPatch generated by **{generator}**.\n\n"
        f"Pull request for human review: {url}\n\n```diff\n{diff}\n```"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
