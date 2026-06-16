"""
DELIBERATELY VULNERABLE WEB APP — FOR AUTHORIZED SECURITY TESTING ONLY
Do NOT deploy this in production or expose to the public internet.
"""

import re
import secrets
import shlex
import socket
import sqlite3
import os
import hashlib
import subprocess
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, make_response, g
)

app = Flask(__name__, template_folder="../templates", static_folder="../static")
# FIX: secret key is now sourced from the environment (with a random per-process
# fallback for local/dev use) instead of being a weak hardcoded string. This
# prevents an attacker who leaks the source from forging signed session cookies.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

DB_PATH = "/tmp/vulnapp.db"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user',
            email    TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title   TEXT,
            content TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            author  TEXT,
            body    TEXT
        )
    """)
    # Seed users — VULN: plain MD5 passwords, weak/common passwords
    users = [
        ("admin",   hashlib.md5(b"admin123").hexdigest(),   "admin", "admin@corp.local"),
        ("alice",   hashlib.md5(b"password").hexdigest(),   "user",  "alice@corp.local"),
        ("bob",     hashlib.md5(b"bob123").hexdigest(),     "user",  "bob@corp.local"),
        ("charlie", hashlib.md5(b"charlie!").hexdigest(),   "user",  "charlie@corp.local"),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?,?,?,?)",
        users,
    )
    notes = [
        (1, "Secret Note",   "Admin secret: FLAG{idor_success}"),
        (2, "Alice's diary", "Dear diary, today was great."),
        (3, "Bob's note",    "My bank PIN is 1234."),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO notes (user_id, title, content) VALUES (?,?,?)",
        notes,
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN: SQL Injection — string interpolation, no parameterisation
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{pw_hash}'"
        )
        try:
            db = get_db()
            user = db.execute(query).fetchone()
        except Exception as e:
            error = str(e)  # VULN: leaks DB error detail to user
            return render_template("login.html", error=error)

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            # VULN: session fixation — session ID not regenerated on login
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials"
            # VULN: no rate limiting or account lockout
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # VULN: IDOR — shows all notes link, user can enumerate by changing note ID
    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    comments = db.execute("SELECT * FROM comments").fetchall()
    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        notes=notes,
        comments=comments,
    )


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # VULN: IDOR — no ownership check; any logged-in user can read any note
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return "Note not found", 404
    return render_template("note.html", note=note)


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    db = get_db()
    # VULN: SQL Injection in search
    results = db.execute(
        f"SELECT * FROM notes WHERE title LIKE '%{q}%' OR content LIKE '%{q}%'"
    ).fetchall()
    # VULN: Reflected XSS — q echoed unescaped into template via |safe
    return render_template("search.html", query=q, results=results)


@app.route("/comment", methods=["POST"])
def post_comment():
    if "user_id" not in session:
        return redirect(url_for("login"))
    author  = request.form.get("author", session["username"])
    body    = request.form.get("body", "")
    db = get_db()
    # VULN: Stored XSS — body stored and rendered unescaped
    db.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, body))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # VULN: IDOR — no check that session user matches user_id
    user = db.execute(
        "SELECT id, username, role, email FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", user=user)


@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    # FIX: Broken Access Control — the role must be re-verified against the
    # server-side record on every request rather than trusted from the signed
    # session cookie. A tampered/forged cookie claiming role=admin is no longer
    # sufficient; the actual DB row for the session's user_id is authoritative.
    current_user = db.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] != "admin":
        return "Access denied", 403
    # Keep the session in sync with the authoritative role.
    session["role"] = current_user["role"]
    users = db.execute("SELECT id, username, role, email, password FROM users").fetchall()
    return render_template("admin.html", users=users)


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*$"
)


@app.route("/ping")
def ping():
    if "user_id" not in session:
        return redirect(url_for("login"))
    host = request.args.get("host", "127.0.0.1")
    # FIX: Command Injection — no more shell=True / string interpolation.
    # Input is strictly validated as a hostname/IP (also confirmed resolvable)
    # and passed as an argv list, so shell metacharacters can't be injected.
    if not _HOSTNAME_RE.match(host):
        result = "Invalid host"
    else:
        try:
            socket.gethostbyname(host)
        except socket.error:
            result = "Invalid host"
        else:
            try:
                result = subprocess.check_output(
                    ["ping", "-c", "1", host],
                    shell=False,
                    stderr=subprocess.STDOUT,
                    timeout=5,
                ).decode("utf-8", errors="replace")
            except subprocess.CalledProcessError as e:
                result = e.output.decode("utf-8", errors="replace")
            except Exception as e:
                result = str(e)
    return render_template("ping.html", host=host, result=result)


# ---------------------------------------------------------------------------
# Bootstrap DB on first request
# ---------------------------------------------------------------------------

with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True, port=5000)  # VULN: debug=True exposes interactive debugger
