import json
import os
import shutil

import pytest

import remediate_agent as agent
import secret_scan

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATES = os.path.join(ROOT, "demo-states")


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


# ------------------------------------------------------------------ secret scan

def test_repository_has_no_hardcoded_secrets():
    assert secret_scan.scan_paths([os.path.join(ROOT, "app.py"), os.path.join(ROOT, "Dockerfile")]) == []


def test_secret_scan_flags_vulnerable_profile():
    findings = secret_scan.scan_text(read(STATES, "vulnerable", "app.py"), "app.py")
    names = {f["message"].split("'")[1] for f in findings}
    assert {"SECRET_KEY", "DB_PASSWORD"} <= names


@pytest.mark.parametrize("line", [
    'API_KEY = os.environ.get("API_KEY")',
    'password = "changeme"',
    'token = "<your-token>"',
    'SECRET = "abc123"  # nosec',
])
def test_secret_scan_ignores_safe_lines(line):
    assert secret_scan.scan_text(line, "x.py") == []


# ------------------------------------------------------------------ agent

TRIVY_REPORT = {"Results": [{"Target": "sample-app:latest (debian 12)", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.11",
     "FixedVersion": "3.0.13", "Severity": "CRITICAL"},
]}]}


def test_trivy_findings_are_parsed():
    findings = agent.trivy_findings(TRIVY_REPORT)
    assert findings[0]["rule"] == "CVE-2024-0001"
    assert findings[0]["file"] == "Dockerfile"
    assert agent.trivy_findings(None) == []


@pytest.mark.parametrize("sources, expected", [
    (["secret-scan"], "secret"), (["trivy"], "image"), (["sonarcloud", "trivy"], "all"), ([], None),
])
def test_auto_mode_selection(sources, expected):
    assert agent.resolve_mode("auto", [{"source": s} for s in sources]) == expected


def test_extract_json_tolerates_fences_and_chatter():
    reply = 'Sure! Here is the fix:\n```json\n{"explanation": "ok", "files": []}\n```'
    assert agent.extract_json(reply) == {"explanation": "ok", "files": []}


@pytest.mark.parametrize("state, mode", [
    ("vulnerable", "all"), ("agent-secret-only", "secret"), ("agent-image-only", "image"),
])
def test_rule_based_fix_repairs_each_profile(state, mode):
    original = {"app.py": read(STATES, state, "app.py"), "Dockerfile": read(STATES, state, "Dockerfile")}
    proposal = agent.rule_based_fix(mode, original)
    assert agent.validate_patch(proposal, original, mode) == []
    if "app.py" in proposal["files"]:
        assert secret_scan.scan_text(proposal["files"]["app.py"], "app.py") == []
    if "Dockerfile" in proposal["files"]:
        assert "FROM python:3.12-slim" in proposal["files"]["Dockerfile"]


def test_validation_rejects_disallowed_or_broken_patches():
    original = {"app.py": read(ROOT, "app.py")}
    proposal = {"explanation": "", "files": {
        ".github/workflows/pipeline.yml": "on: push",
        "app.py": "def broken(:\n",
    }}
    problems = agent.validate_patch(proposal, original, "secret")
    assert any("allow-list" in p for p in problems)
    assert any("does not compile" in p for p in problems)


def test_validation_rejects_patch_that_keeps_secret():
    vulnerable = read(STATES, "vulnerable", "app.py")
    proposal = {"explanation": "", "files": {"app.py": vulnerable + "\n# touched\n"}}
    assert any("hardcoded secret" in p for p in agent.validate_patch(proposal, {"app.py": vulnerable}, "secret"))


def test_model_patch_is_used_when_valid(monkeypatch, tmp_path):
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "agent-secret-only", name), tmp_path / name)
    fixed_app = read(STATES, "fixed", "app.py")

    def fake_call(findings, files, model, api_key):
        assert "SECRET_KEY" in files["app.py"]
        return {"explanation": "Moved the secret to APP_SECRET_KEY.", "files": {"app.py": fixed_app}}

    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr(agent, "call_nim", fake_call)
    args = agent.parse_args(["--repo-root", str(tmp_path), "--provider", "auto", "--dry-run"])
    proposal, _, generator = agent.generate_patch(args, "secret", [])
    assert generator.startswith("NVIDIA NIM")
    assert proposal["files"]["app.py"] == fixed_app


def test_agent_falls_back_when_model_patch_is_bad(monkeypatch, tmp_path):
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "agent-secret-only", name), tmp_path / name)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setattr(agent, "call_nim", lambda *a: {"explanation": "", "files": {"app.py": "oops("}})
    args = agent.parse_args(["--repo-root", str(tmp_path), "--dry-run"])
    proposal, _, generator = agent.generate_patch(args, "secret", [])
    assert generator == "rule-based fallback"
    assert "os.environ.get" in proposal["files"]["app.py"]


def test_agent_dry_run_end_to_end(monkeypatch, tmp_path, capsys):
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "vulnerable", name), tmp_path / name)
    (tmp_path / "trivy-results.json").write_text(json.dumps(TRIVY_REPORT))
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    code = agent.main(["--repo-root", str(tmp_path), "--trivy-report", str(tmp_path / "trivy-results.json"),
                       "--secret-report", str(tmp_path / "none.json"), "--dry-run"])
    out = capsys.readouterr().out
    assert code == 0
    assert "mode: all" in out
    assert "+FROM python:3.12-slim" in out
    # dry run must not touch the working tree
    assert "SuperSecret@123" in (tmp_path / "app.py").read_text()


def test_pr_body_states_human_review():
    body = agent.build_pr_body("secret", [{"source": "secret-scan", "rule": "hardcoded-credential",
                                           "severity": "CRITICAL", "file": "app.py", "line": 25}],
                               {"explanation": "x", "files": {"app.py": ""}}, "rule-based fallback", "")
    assert "Human review required" in body and "`app.py`:25" in body
