"""Demo web application."""

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
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'user'
        )
        """
    )
    db.commit()

    # Seed default users.
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
            db.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, password, role),
            )
    db.commit()
    db.close()


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
# Routes – require login
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
    if "user_id" not in session:
        return redirect(url_for("login"))

    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("profile.html", user=user)


@app.route("/change-role", methods=["POST"])
def change_role():
    if "user_id" not in session:
        return redirect(url_for("login"))

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
# Routes – admin
# ---------------------------------------------------------------------------

@app.route("/admin")
def admin():
    db    = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/api/users")
def api_users():
    db    = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify([dict(u) for u in users])


if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
