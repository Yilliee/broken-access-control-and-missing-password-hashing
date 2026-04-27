"""
Vulnerable Demo Application
============================
This application intentionally contains security vulnerabilities for educational purposes.

Vulnerabilities demonstrated:
  1. Missing Password Hashing  – passwords are stored and compared as plaintext.
  2. Broken Access Control (Accidental) – /profile/<id> checks login status but
       forgets to verify that the requesting user owns the profile.
  3. Broken Access Control (Explicit)  – /admin and /api/users have NO authentication
       check at all; any anonymous visitor can reach them.
  4. Broken Access Control (Accidental) – /change-role checks that someone is logged
       in but never checks whether they are an admin.

DO NOT deploy this application in a production environment.
"""

import os
import sqlite3

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "dev-secret-key-not-for-production"

DATABASE = os.path.join(app.root_path, "users.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed default users the first time the app starts."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            email    TEXT    NOT NULL,
            password TEXT    NOT NULL,   -- VULNERABILITY: stored as plaintext
            role     TEXT    NOT NULL DEFAULT 'user'
        )
        """
    )
    db.commit()

    # Seed two users so there is always something to demonstrate with.
    seed_users = [
        ("admin",   "admin@example.com",  "adminpass",  "admin"),
        ("alice",   "alice@example.com",  "alice1234",  "user"),
        ("bob",     "bob@example.com",    "bobsecret",  "user"),
    ]
    for username, email, password, role in seed_users:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not existing:
            # VULNERABILITY: password saved without hashing
            db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, password, role),
            )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Routes – public
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            flash("Username already taken.", "danger")
            return render_template("register.html")

        # ----------------------------------------------------------------
        # VULNERABILITY #1 – Missing Password Hashing
        # The password is stored in the database exactly as the user typed
        # it.  A secure implementation would use bcrypt / argon2 / PBKDF2.
        # ----------------------------------------------------------------
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, password, "user"),
        )
        db.commit()
        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        # ----------------------------------------------------------------
        # VULNERABILITY #1 (continued) – Plaintext password comparison
        # A secure implementation would use e.g. bcrypt.check_password_hash
        # ----------------------------------------------------------------
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes – require login (but access control is broken in some of them)
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("dashboard.html", users=users)


@app.route("/profile/<int:user_id>")
def profile(user_id):
    # Checks that the visitor is logged in …
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ----------------------------------------------------------------
    # VULNERABILITY #2 – Accidental Broken Access Control
    # The developer remembered to require login but forgot to check that
    # the logged-in user is actually allowed to view THIS profile.
    # Any authenticated user can view any other user's profile by simply
    # changing the number in the URL (e.g. /profile/1, /profile/2 …).
    # A secure implementation would add:
    #   if session["user_id"] != user_id and session["role"] != "admin":
    #       abort(403)
    # ----------------------------------------------------------------
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("profile.html", user=user)


@app.route("/change-role", methods=["POST"])
def change_role():
    # Checks that the visitor is logged in …
    if "user_id" not in session:
        return redirect(url_for("login"))

    # ----------------------------------------------------------------
    # VULNERABILITY #3 – Accidental Broken Access Control
    # The developer added a login check but forgot to also verify that
    # the requester is an admin.  Any ordinary user can promote themselves
    # (or anyone else) to admin by submitting the form directly.
    # A secure implementation would also check:
    #   if session["role"] != "admin":
    #       abort(403)
    # ----------------------------------------------------------------
    target_user_id = request.form.get("user_id", type=int)
    new_role       = request.form.get("role", "user")

    if new_role not in ("user", "admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_user_id))
    db.commit()
    flash("Role updated successfully.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Routes – admin (completely unprotected – explicit broken access control)
# ---------------------------------------------------------------------------

@app.route("/admin")
def admin():
    # ----------------------------------------------------------------
    # VULNERABILITY #4 – Explicit Broken Access Control
    # This route is intended for admins only, but there is NO authentication
    # or authorisation check whatsoever.  Any anonymous visitor who knows
    # (or guesses) the URL can access the full admin panel.
    # A secure implementation would verify both that the user is logged in
    # and that their role is 'admin'.
    # ----------------------------------------------------------------
    db    = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/api/users")
def api_users():
    # ----------------------------------------------------------------
    # VULNERABILITY #5 – Explicit Broken Access Control (API endpoint)
    # Exposes every user record – including plaintext passwords – as JSON
    # with no authentication check at all.
    # ----------------------------------------------------------------
    db    = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify([dict(u) for u in users])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
