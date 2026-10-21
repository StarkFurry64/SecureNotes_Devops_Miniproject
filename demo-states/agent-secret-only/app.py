"""SecureNotes - a small Flask notes application used as the target of the
DevSecOps pipeline in .github/workflows/pipeline.yml.

Notes are kept in a thread-safe in-memory list and are lost when the
container restarts. That is intentional: the project is about the pipeline,
not about the application.
"""

import hmac
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for

load_dotenv()

SERVICE_NAME = "securenotes"
MAX_NOTE_LENGTH = 500
NOTE_ID_PATTERN = re.compile(r"^[0-9a-f]{8}$")
CSRF_SESSION_FIELD = "_csrf"
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}

app = Flask(__name__)  # NOSONAR(S4502): CSRF is enforced for every POST by verify_csrf_token() below
# DEMO DEFECT: credentials hardcoded in source (SonarCloud python:S6779 / S2068).
app.config["SECRET_KEY"] = "sn-prod-8f3k2LmQ9xZt7Wv1"
DB_PASSWORD = "SuperSecret@123"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

_notes = []
_notes_lock = threading.Lock()


def csrf_token():
    """Per-session token embedded in every form and checked on every POST."""
    token = session.get(CSRF_SESSION_FIELD)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_FIELD] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def verify_csrf_token():
    if request.method != "POST":
        return
    expected = session.get(CSRF_SESSION_FIELD, "")
    sent = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="Missing or invalid CSRF token.")


@app.after_request
def add_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


def get_notes():
    with _notes_lock:
        return list(_notes)


def clear_notes():
    with _notes_lock:
        _notes.clear()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", notes=get_notes())


@app.route("/add", methods=["POST"])
def add_note():
    # DEMO DEFECT: validation duplicated inline in each route (code smell).
    raw = request.form.get("text")
    if raw is None:
        flash("Input is missing.", "error")
        return redirect(url_for("index"))
    text = raw.strip()
    if not text:
        flash("Input cannot be empty.", "error")
        return redirect(url_for("index"))
    if len(text) > MAX_NOTE_LENGTH:
        flash(f"Note is longer than {MAX_NOTE_LENGTH} characters.", "error")
        return redirect(url_for("index"))
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in text):
        flash("Note contains control characters.", "error")
        return redirect(url_for("index"))

    note = {
        "id": uuid.uuid4().hex[:8],
        "text": text,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    with _notes_lock:
        _notes.insert(0, note)
    flash("Note added.", "success")
    return redirect(url_for("index"))


@app.route("/delete/<note_id>", methods=["POST"])
def delete_note(note_id):
    # DEMO DEFECT: the same validation copied again.
    cleaned_id = note_id.strip()
    if not NOTE_ID_PATTERN.match(cleaned_id):
        flash("Invalid note id.", "error")
        return redirect(url_for("index"))

    with _notes_lock:
        for position, note in enumerate(_notes):
            if note["id"] == cleaned_id:
                del _notes[position]
                flash("Note deleted.", "success")
                break
        else:
            flash("Note not found.", "error")
    return redirect(url_for("index"))


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        status="healthy",
        service=SERVICE_NAME,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host="127.0.0.1", port=port)
