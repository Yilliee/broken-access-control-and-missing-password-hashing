# Broken Access Control & Missing Password Hashing – Demo Site

> ⚠️ **This application is intentionally insecure.  For educational purposes only.
> Do NOT deploy it in a production environment.**

A small Flask web application that demonstrates two common security vulnerabilities
side-by-side:

1. **Missing Password Hashing** – passwords are stored and compared as plaintext.
2. **Broken Access Control (Accidental)** – routes that check *login* status but forget
   to check *ownership* or *role*.
3. **Broken Access Control (Explicit)** – routes with no authentication check at all.

---

## Vulnerabilities

| # | Name | Route | Type |
|---|------|--------|------|
| 1 | Missing Password Hashing | `/register`, `/login` | Missing control |
| 2 | IDOR – profile page | `/profile/<id>` | Accidental BAC |
| 3 | Privilege escalation – role change | `/change-role` | Accidental BAC |
| 4 | Unprotected admin panel | `/admin` | Explicit BAC |
| 5 | Unauthenticated API leaking passwords | `/api/users` | Explicit BAC |

---

## Quick Start

### Prerequisites

* Python 3.8 or newer
* `pip`

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the app

```bash
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

The SQLite database (`users.db`) is created automatically on first run with three
seed accounts:

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | adminpass | admin |
| alice    | alice1234 | user  |
| bob      | bobsecret | user  |

---

## Exploring the Vulnerabilities

### 1 – Missing Password Hashing

Register a new account, then visit `/api/users` (no login required) – your password
appears in the JSON response exactly as you typed it.

### 2 – Accidental IDOR (profile page)

1. Log in as `alice` / `alice1234`.
2. Visit `/profile/1` – you can see the **admin** account's profile (and password).
3. The server only checked that you were *logged in*, not that you *own* profile #1.

### 3 – Accidental Privilege Escalation (role change)

1. Log in as `alice` / `alice1234`.
2. Go to the Dashboard.
3. Use the **Change User Role** form to promote yourself to `admin`.
4. The server only checked that you were *logged in*, not that you are an *admin*.

### 4 – Explicit Broken Access Control (admin panel)

Visit `/admin` without logging in – you get the full admin view of all users,
including their plaintext passwords.  No credentials are needed.

### 5 – Explicit Broken Access Control (JSON API)

Visit `/api/users` without logging in – you receive a JSON array of every user
record, including plaintext passwords.

---

## Project Structure

```
app.py              – Flask application (all vulnerabilities are annotated)
requirements.txt    – Python dependencies
templates/
  base.html         – Shared layout (Bootstrap 5 via CDN)
  index.html        – Home page with vulnerability explanations
  register.html     – Registration form
  login.html        – Login form
  dashboard.html    – User dashboard (IDOR links + role-change form)
  profile.html      – User profile page (IDOR target)
  admin.html        – Admin panel (no auth check)
```
