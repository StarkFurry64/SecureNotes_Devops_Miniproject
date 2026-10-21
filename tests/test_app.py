import pytest

import app as securenotes


class CsrfClient:
    """Test client that sends the session's CSRF token with every POST, like the real form does."""

    def __init__(self, client):
        self.raw = client
        client.get("/")
        with client.session_transaction() as session:
            self.token = session[securenotes.CSRF_SESSION_FIELD]

    def get(self, *args, **kwargs):
        return self.raw.get(*args, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.raw.post(url, data={**(data or {}), "csrf_token": self.token}, **kwargs)


@pytest.fixture
def client():
    securenotes.app.config["TESTING"] = True
    securenotes.clear_notes()
    with securenotes.app.test_client() as test_client:
        yield CsrfClient(test_client)
    securenotes.clear_notes()


def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecureNotes" in response.data
    assert b"No notes yet" in response.data


def test_add_note_creates_note_and_redirects(client):
    response = client.post("/add", data={"text": "  first note  "})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    notes = securenotes.get_notes()
    assert len(notes) == 1
    assert notes[0]["text"] == "first note"
    assert len(notes[0]["id"]) == 8

    client.post("/add", data={"text": "second note"})
    assert securenotes.get_notes()[0]["text"] == "second note"


@pytest.mark.parametrize("bad_text", ["", "   ", "\n\t", "x" * 501, "bad\x00byte"])
def test_add_note_rejects_invalid_input(client, bad_text):
    response = client.post("/add", data={"text": bad_text}, follow_redirects=True)
    assert response.status_code == 200
    assert securenotes.get_notes() == []


def test_add_note_without_text_field_is_rejected(client):
    response = client.post("/add", data={}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Input is missing." in response.data
    assert securenotes.get_notes() == []


def test_delete_note_removes_it(client):
    client.post("/add", data={"text": "to delete"})
    note_id = securenotes.get_notes()[0]["id"]

    response = client.post(f"/delete/{note_id}")
    assert response.status_code == 302
    assert securenotes.get_notes() == []


@pytest.mark.parametrize("bad_id", ["not-an-id", "ZZZZZZZZ", "abc", "deadbeef"])
def test_delete_rejects_invalid_or_unknown_id(client, bad_id):
    client.post("/add", data={"text": "keep me"})
    response = client.post(f"/delete/{bad_id}", follow_redirects=True)
    assert response.status_code == 200
    assert len(securenotes.get_notes()) == 1


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "healthy"
    assert body["service"] == "securenotes"
    assert "T" in body["timestamp"]


@pytest.mark.parametrize("token", [None, "forged-token"])
def test_post_without_valid_csrf_token_is_rejected(client, token):
    data = {"text": "csrf attack"} if token is None else {"text": "csrf attack", "csrf_token": token}
    response = client.raw.post("/add", data=data)
    assert response.status_code == 400
    assert securenotes.get_notes() == []


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert b'name="csrf_token"' in response.data
