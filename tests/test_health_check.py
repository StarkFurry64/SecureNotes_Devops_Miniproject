import threading

import pytest
import requests
from werkzeug.serving import make_server

import app as securenotes
import health_check as hc


class FakeResponse:
    def __init__(self, status_code=200, body=None, raw=None):
        self.status_code = status_code
        self._body = body
        self._raw = raw

    def json(self):
        if self._raw is not None:
            raise ValueError("not json")
        return self._body


class FakeSession:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.posts = response, exc, []

    def get(self, url, timeout):
        if self.exc:
            raise self.exc
        return self.response

    def post(self, url, json, timeout):
        self.posts.append(json)
        return FakeResponse(204)


@pytest.fixture
def live_server():
    server = make_server("127.0.0.1", 0, securenotes.app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_live_app_is_healthy(live_server):
    result = hc.check_health(f"{live_server}/health")
    assert result.result == hc.HEALTHY
    assert result.status_code == 200
    assert set(result.checks.values()) == {"PASS"}


def test_connection_refused_is_unhealthy():
    session = FakeSession(exc=requests.exceptions.ConnectionError("refused"))
    result = hc.check_health("http://x/health", session=session)
    assert result.result == hc.UNHEALTHY
    assert result.checks == {"connectivity": "FAIL"}
    assert "Connection failed" in result.detail


def test_timeout_is_unhealthy():
    session = FakeSession(exc=requests.exceptions.Timeout())
    result = hc.check_health("http://x/health", timeout=2, session=session)
    assert result.result == hc.UNHEALTHY
    assert "Timeout" in result.detail


def test_server_error_is_unhealthy():
    session = FakeSession(FakeResponse(500, {"status": "healthy"}))
    result = hc.check_health("http://x/health", session=session)
    assert result.result == hc.UNHEALTHY
    assert result.checks["http_status"] == "FAIL"


def test_wrong_body_is_unhealthy_even_with_200():
    session = FakeSession(FakeResponse(200, {"status": "error"}))
    result = hc.check_health("http://x/health", session=session)
    assert result.result == hc.UNHEALTHY
    assert result.checks["response_body"] == "FAIL"


def test_non_json_body_is_unhealthy():
    session = FakeSession(FakeResponse(200, raw="<html>"))
    assert hc.check_health("http://x/health", session=session).result == hc.UNHEALTHY


@pytest.mark.parametrize("warn_ms, fail_ms, expected", [(-1, 10_000, hc.WARNING), (-2, -1, hc.UNHEALTHY)])
def test_response_time_thresholds(warn_ms, fail_ms, expected):
    session = FakeSession(FakeResponse(200, {"status": "healthy"}))
    result = hc.check_health("http://x/health", warn_ms=warn_ms, fail_ms=fail_ms, session=session)
    assert result.result == expected


def test_history_and_availability(tmp_path):
    path = tmp_path / "history.csv"
    up = hc.CheckResult("u", hc.HEALTHY, 200, 100.0)
    slow = hc.CheckResult("u", hc.WARNING, 200, 700.0)
    down = hc.CheckResult("u", hc.UNHEALTHY, detail="Connection failed")
    for result in (up, up, slow, down):
        hc.append_history(result, str(path))

    stats = hc.summarise(hc.load_history(str(path)))
    assert stats["total_checks"] == 4
    assert stats["failed"] == 1
    assert stats["availability_pct"] == 75.0
    assert stats["avg_response_ms"] == 300.0


def test_alert_payload_works_for_discord_and_slack():
    session = FakeSession()
    down = hc.CheckResult("http://x/health", hc.UNHEALTHY, detail="Timeout")
    assert hc.send_alert("https://hooks.example/abc", down, session=session)
    payload = session.posts[0]
    assert "API Health ALERT" in payload["content"] and payload["text"] == payload["content"]
    assert hc.send_alert("", down, session=session) is False


def test_main_exit_codes(tmp_path, live_server):
    history = str(tmp_path / "h.csv")
    assert hc.main(["--url", f"{live_server}/health", "--history", history]) == 0
    assert hc.main(["--url", "http://127.0.0.1:9/health", "--history", history,
                    "--retries", "0", "--timeout", "1"]) == 1
    assert hc.main(["--report", "--history", history]) == 0


def test_load_test_generates_mixed_traffic(live_server, capsys):
    import load_test

    securenotes.clear_notes()
    assert load_test.main(["--url", live_server, "--duration", "1", "--workers", "2"]) == 0
    out = capsys.readouterr().out
    assert "home page -> 200" in out
    assert "404 page -> 404" in out
    assert securenotes.get_notes()  # notes were really created through the CSRF-protected form
    securenotes.clear_notes()
