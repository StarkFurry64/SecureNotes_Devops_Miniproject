"""Agent and scanner paths that talk to external systems, exercised with fakes:
SonarCloud and NVIDIA NIM over HTTP, and GitHub through a real local git remote."""

import json
import os
import shutil
import subprocess

import pytest
import requests

import health_check as hc
import remediate_agent as agent
import secret_scan

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATES = os.path.join(ROOT, "demo-states")


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload, self.status_code = payload, status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")


# ------------------------------------------------------------------ SonarCloud

class FakeSonar:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def get(self, url, params, headers, timeout):
        self.calls.append((url, params, headers))
        if self.fail:
            raise requests.exceptions.ConnectionError("down")
        if url.endswith("/api/issues/search"):
            return FakeResponse({"issues": [{"rule": "python:S6779", "component": "proj:app.py", "line": 27,
                                             "severity": "BLOCKER", "message": "Don't disclose Flask secret keys."}]})
        return FakeResponse({"hotspots": [{"ruleKey": "python:S2068", "component": "proj:app.py", "line": 28,
                                           "vulnerabilityProbability": "HIGH", "message": "Review this password."}]})


def test_sonar_findings_parse_issues_and_hotspots():
    fake = FakeSonar()
    findings = agent.sonar_findings("proj", "token", session=fake)
    assert [f["rule"] for f in findings] == ["python:S6779", "python:S2068"]
    assert all(f["file"] == "app.py" and f["source"] == "sonarcloud" for f in findings)
    assert fake.calls[0][2] == {"Authorization": "Bearer token"}


def test_sonar_findings_degrade_gracefully():
    assert agent.sonar_findings("proj", "", session=FakeSonar()) == []
    assert agent.sonar_findings("proj", "token", session=FakeSonar(fail=True)) == []


def test_relevant_findings_are_scoped_to_editable_files():
    findings = [
        {"source": "sonarcloud", "file": "app.py"},
        {"source": "sonarcloud", "file": "monitor/health_check.py"},
        {"source": "trivy", "file": "Dockerfile"},
    ]
    assert agent.relevant_findings("secret", findings) == [findings[0]]
    assert agent.relevant_findings("image", findings) == [findings[2]]
    assert agent.relevant_findings("all", findings) == [findings[0], findings[2]]


# ------------------------------------------------------------------ NVIDIA NIM

class FakeNim:
    def __init__(self, content):
        self.content, self.request = content, None

    def post(self, url, headers, json, timeout):
        self.request = (url, headers, json)
        return FakeResponse({"choices": [{"message": {"content": self.content}}]})


def test_call_nim_sends_findings_and_parses_reply():
    reply = '```json\n{"explanation": "Use env var.", "files": [{"path": "app.py", "content": "x = 1\\n"}, "junk"]}\n```'
    fake = FakeNim(reply)
    findings = [{"source": "secret-scan", "rule": "hardcoded-credential", "severity": "CRITICAL",
                 "file": "app.py", "line": 27, "message": "secret"}]
    proposal = agent.call_nim(findings, {"app.py": "SECRET = 'x'\n"}, "test-model", "key", session=fake)

    url, headers, body = fake.request
    assert url == agent.NIM_URL and headers["Authorization"] == "Bearer key"
    assert body["model"] == "test-model" and body["messages"][0]["role"] == "system"
    assert "=== FILE: app.py ===" in body["messages"][1]["content"]
    assert proposal == {"explanation": "Use env var.", "files": {"app.py": "x = 1\n"}}


def test_extract_json_rejects_non_json():
    with pytest.raises(ValueError):
        agent.extract_json("I cannot help with that.")


def test_prompt_truncates_long_finding_lists():
    findings = [{"source": "trivy", "rule": f"CVE-{i}", "severity": "HIGH", "file": "Dockerfile", "message": "m"}
                for i in range(50)]
    assert "and 10 more findings" in agent.build_user_prompt(findings, {})


def test_provider_nim_without_key_gives_no_patch(monkeypatch, tmp_path):
    shutil.copy(os.path.join(STATES, "agent-secret-only", "app.py"), tmp_path / "app.py")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    args = agent.parse_args(["--repo-root", str(tmp_path), "--provider", "nim"])
    assert agent.generate_patch(args, "secret", [])[0] is None


def test_provider_nim_failure_gives_no_patch(monkeypatch, tmp_path):
    shutil.copy(os.path.join(STATES, "agent-secret-only", "app.py"), tmp_path / "app.py")
    monkeypatch.setenv("NVIDIA_API_KEY", "k")

    def boom(*_):
        raise requests.exceptions.ConnectionError("no route")

    monkeypatch.setattr(agent, "call_nim", boom)
    args = agent.parse_args(["--repo-root", str(tmp_path), "--provider", "nim"])
    assert agent.generate_patch(args, "secret", [])[0] is None


def test_fixed_code_needs_no_patch(monkeypatch, tmp_path, capsys):
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "fixed", name), tmp_path / name)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    code = agent.main(["--repo-root", str(tmp_path), "--trivy-report", "none.json", "--secret-report", "none.json"])
    assert code == 0 and "nothing to do" in capsys.readouterr().out


def test_forced_mode_without_fixable_issue_fails(monkeypatch, tmp_path):
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "fixed", name), tmp_path / name)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    code = agent.main(["--repo-root", str(tmp_path), "--mode", "secret", "--trivy-report", "none.json",
                       "--secret-report", "none.json"])
    assert code == 1 and "No acceptable patch" in summary.read_text()


# ------------------------------------------------------------------ GitHub pull request

def run(*cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo_with_remote(tmp_path):
    remote, work = tmp_path / "remote.git", tmp_path / "work"
    run("git", "init", "--bare", "-b", "main", str(remote), cwd=tmp_path)
    run("git", "init", "-b", "main", str(work), cwd=tmp_path)
    for name in ("app.py", "Dockerfile"):
        shutil.copy(os.path.join(STATES, "agent-secret-only", name), work / name)
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "add", ".", cwd=work)
    run("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "init", cwd=work)
    run("git", "remote", "add", "origin", str(remote), cwd=work)
    run("git", "push", "origin", "main", cwd=work)
    return work, remote


class FakeGitHub:
    def __init__(self, open_prs=(), create_status=201):
        self.open_prs, self.create_status, self.created = list(open_prs), create_status, None

    def get(self, url, headers, params, timeout):
        assert url.endswith("/repos/acme/securenotes/pulls")
        return FakeResponse(self.open_prs)

    def post(self, url, headers, timeout, json):
        self.created = json
        return FakeResponse({"html_url": "https://github.com/acme/securenotes/pull/7"}, self.create_status)


@pytest.fixture
def github_env(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/securenotes")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_test")
    monkeypatch.setenv("GITHUB_RUN_ID", "4242")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("SONAR_TOKEN", raising=False)


def test_agent_pushes_branch_and_opens_pr(repo_with_remote, github_env, monkeypatch, tmp_path):
    work, remote = repo_with_remote
    fake = FakeGitHub()
    monkeypatch.setattr(agent, "requests", fake)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))

    code = agent.main(["--repo-root", str(work), "--mode", "secret", "--trivy-report", "none.json",
                       "--secret-report", "none.json"])

    assert code == 0
    assert fake.created["head"] == "acme:ai-remediation/secret-4242"
    assert fake.created["base"] == "main"
    assert fake.created["title"].startswith("[AI Remediation] secret")
    assert "Human review required" in fake.created["body"]
    # The fix lives on the new branch in the remote; main is untouched.
    branch_app = subprocess.run(["git", "show", "ai-remediation/secret-4242:app.py"], cwd=remote,
                                check=True, capture_output=True, text=True).stdout
    main_app = subprocess.run(["git", "show", "main:app.py"], cwd=remote,
                              check=True, capture_output=True, text=True).stdout
    assert 'os.environ.get("APP_SECRET_KEY"' in branch_app
    assert "SuperSecret@123" in main_app
    assert "pull/7" in (tmp_path / "summary.md").read_text()


def test_agent_skips_when_remediation_pr_already_open(repo_with_remote, github_env, monkeypatch):
    work, _ = repo_with_remote
    fake = FakeGitHub(open_prs=[{"title": "[AI Remediation] secret: fix 2 security finding(s)",
                                 "html_url": "https://github.com/acme/securenotes/pull/3"}])
    monkeypatch.setattr(agent, "requests", fake)
    args = agent.parse_args(["--repo-root", str(work)])
    url = agent.open_pull_request(args, "secret", [], {"explanation": "", "files": {}}, "rules")
    assert url.endswith("/pull/3") and fake.created is None


def test_agent_explains_missing_actions_pr_permission(repo_with_remote, github_env, monkeypatch):
    work, _ = repo_with_remote
    monkeypatch.setattr(agent, "requests", FakeGitHub(create_status=403))
    args = agent.parse_args(["--repo-root", str(work)])
    proposal = {"explanation": "x", "files": {"app.py": "import os\n"}}
    with pytest.raises(RuntimeError, match="Allow GitHub Actions to create"):
        agent.open_pull_request(args, "secret", [], proposal, "rules")


def test_agent_requires_github_context(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(RuntimeError):
        agent.open_pull_request(agent.parse_args(["--repo-root", str(tmp_path)]), "secret", [], {}, "rules")


# ------------------------------------------------------------------ scanner and monitor CLIs

def test_secret_scan_cli_writes_report_and_fails(tmp_path, capsys):
    shutil.copy(os.path.join(STATES, "vulnerable", "app.py"), tmp_path / "app.py")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text('PASSWORD = "ignored-in-tests"\n')
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    report = tmp_path / "out.json"

    assert secret_scan.main([str(tmp_path), "--output", str(report)]) == 1
    findings = json.loads(report.read_text())
    assert len(findings) == 2 and all(f["file"].endswith("app.py") for f in findings)
    assert "2 hardcoded secret(s)" in capsys.readouterr().out


def test_secret_scan_cli_passes_on_clean_tree(tmp_path):
    shutil.copy(os.path.join(STATES, "fixed", "app.py"), tmp_path / "app.py")
    assert secret_scan.main([str(tmp_path)]) == 0


def test_secret_scan_detects_token_formats():
    text = 'key = "AKIA' + "A" * 16 + '"\ntok = "ghp_' + "a" * 36 + '"\n'
    assert {f["rule"] for f in secret_scan.scan_text(text, "x.py")} == {"aws-access-key", "github-token"}


def test_monitor_interval_mode_alerts_on_outage_and_recovery(monkeypatch, tmp_path, capsys):
    sequence = iter([hc.HEALTHY, hc.UNHEALTHY, hc.HEALTHY])
    monkeypatch.setattr(hc, "check_health", lambda *a: hc.CheckResult("u", next(sequence), 200, 10.0))
    monkeypatch.setattr(hc.time, "sleep", lambda _: None)
    alerts = []
    monkeypatch.setattr(hc, "send_alert", lambda url, result, recovered=False: alerts.append((result.result, recovered)))
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    code = hc.main(["--interval", "1", "--count", "3", "--retries", "0", "--history", str(tmp_path / "h.csv"),
                    "--webhook", "https://hooks.example/x"])

    assert code == 0
    assert alerts == [(hc.UNHEALTHY, False), (hc.HEALTHY, True)]
    assert "Availability     : 66.67%" in capsys.readouterr().out
    assert "SecureNotes health" in summary.read_text()


def test_monitor_json_output(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(hc, "check_health", lambda *a: hc.CheckResult("u", hc.HEALTHY, 200, 12.0))
    assert hc.main(["--json", "--history", str(tmp_path / "h.csv")]) == 0
    assert json.loads(capsys.readouterr().out)["history"]["total_checks"] == 1


def test_alert_delivery_failure_is_reported(capsys):
    class Down:
        def post(self, *a, **k):
            raise requests.exceptions.ConnectionError("x")

    assert hc.send_alert("https://hooks.example/x", hc.CheckResult("u", hc.UNHEALTHY), session=Down()) is False
