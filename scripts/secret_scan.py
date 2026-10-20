"""Lightweight hardcoded-secret scanner.

SonarCloud (python:S2068 / S6418 / S6779) is the primary secret check in Stage 1.
This script is a local backstop that runs without any account, so the gate still
works on a fork without SONAR_TOKEN and on SonarCloud's first analysis, where
the default quality gate only judges "new code". Its JSON output is also one of
the inputs of the remediation agent.

Usage: python scripts/secret_scan.py [--output findings.json] [paths...]
Exit code 1 when a secret is found.
"""

import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "tests", "demo-states", "docs", "node_modules", ".scannerwork"}
SCAN_SUFFIXES = (".py", ".yml", ".yaml", ".cfg", ".ini", ".toml", ".json", ".sh", ".ps1")
SCAN_NAMES = {"Dockerfile", "docker-compose.yml"}

SECRET_NAME = r"[A-Za-z0-9_]*(?:secret|password|passwd|pwd|token|api_?key|private_?key)[A-Za-z0-9_]*"
RULES = [
    (
        "hardcoded-credential",
        # SECRET_KEY = "abc"   /   db_password: str = 'abc'
        re.compile(rf"""^\s*(?P<name>{SECRET_NAME})\s*(?::\s*\w+\s*)?=\s*(?P<q>["'])(?P<value>[^"']{{4,}})(?P=q)""", re.I),
    ),
    (
        "hardcoded-credential",
        # app.config["SECRET_KEY"] = "abc"
        re.compile(rf"""\[\s*["'](?P<name>{SECRET_NAME})["']\s*\]\s*=\s*(?P<q>["'])(?P<value>[^"']{{4,}})(?P=q)""", re.I),
    ),
    ("aws-access-key", re.compile(r"(?P<value>AKIA[0-9A-Z]{16})")),
    ("github-token", re.compile(r"(?P<value>gh[pousr]_[A-Za-z0-9]{36,})")),
    ("nvidia-api-key", re.compile(r"(?P<value>nvapi-[A-Za-z0-9_-]{20,})")),
    ("private-key", re.compile(r"(?P<value>-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)")),
]
# Values that are obviously placeholders, not credentials.
PLACEHOLDERS = re.compile(r"^(?:change-?me|changeme|example|placeholder|your[-_].*|<.*>|\$\{.*\}|x+|\*+)$", re.I)


def iter_files(roots):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name in SCAN_NAMES or name.endswith(SCAN_SUFFIXES):
                    yield os.path.join(dirpath, name)


def scan_text(text, path):
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if "nosec" in line or "secret-scan: ignore" in line:
            continue
        for rule, pattern in RULES:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group("value")
            if PLACEHOLDERS.match(value):
                continue
            name = match.groupdict().get("name") or rule
            findings.append({
                "source": "secret-scan",
                "rule": rule,
                "file": os.path.relpath(path).replace(os.sep, "/"),
                "line": line_no,
                "severity": "CRITICAL",
                "message": f"Hardcoded secret assigned to '{name}'. Read it from the environment instead.",
            })
            break
    return findings


def scan_paths(paths):
    findings = []
    for path in iter_files(paths):
        try:
            with open(path, encoding="utf-8") as handle:
                findings.extend(scan_text(handle.read(), path))
        except (UnicodeDecodeError, OSError):
            continue
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", default=["."])
    parser.add_argument("--output", help="write findings as JSON to this file")
    args = parser.parse_args(argv)

    findings = scan_paths(args.paths)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(findings, handle, indent=2)

    if not findings:
        print("Secret scan: no hardcoded secrets found.")
        return 0
    print(f"Secret scan: {len(findings)} hardcoded secret(s) found:")
    for finding in findings:
        print(f"  {finding['file']}:{finding['line']}  [{finding['rule']}] {finding['message']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
