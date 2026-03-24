import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
import user_management as db

# ── Auto-bootstrap the database on every startup ──────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

def _tables_exist():
    """Return True if the required tables are all present."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

init_db()

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# VULNERABILITY: Wildcard CORS — allows ANY origin to make credentialed requests
CORS(app)

# VULNERABILITY: Hardcoded secret key — session cookies can be forged
app.secret_key = "supersecretkey123"

def is_password_strong(password):
    """Check if password meets minimum strength requirements."""
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # VULNERABILITY: Open Redirect — blindly follows 'url' query parameter
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    # Check if user is already logged in
    if 'logged_in' in session and session['logged_in']:
        return redirect("/feed.html")

    # VULNERABILITY: Reflected XSS — 'msg' rendered with |safe in template
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            session['username'] = username
            session['logged_in'] = True
            return redirect("/feed.html")
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")
        if not is_password_strong(password):
            return render_template("signup.html", msg="Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one digit.")
        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect("/", code=302)

    username = session['username']

    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        post_content = request.form["content"]
        # VULNERABILITY: IDOR — username from hidden form field, can be tampered with
        # But now using session, so override with session username
        db.insertPost(username, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)
    else:
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect("/", code=302)

    # VULNERABILITY: No authentication check — any visitor can read any profile
    # VULNERABILITY: SQL Injection via 'user' parameter in getUserProfile()
    if request.args.get("url"):
        return redirect(request.args.get("url"), code=302)
    username = request.args.get("user", session['username'])
    profile_data = db.getUserProfile(username)
    return render_template("profile.html", profile=profile_data, username=username)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect("/", code=302)

    # VULNERABILITY: No authentication — change ?user= to read anyone's inbox
    if request.method == "POST":
        sender    = session['username']
        recipient = request.form.get("recipient", "")
        body      = request.form.get("body", "")
        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(session['username'])
        return render_template("messages.html", messages=msgs, username=sender, recipient=recipient)
    else:
        username = session['username']
        msgs = db.getMessages(username)
        return render_template("messages.html", messages=msgs, username=username, recipient=username)


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


# ── Logout ────────────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="127.0.0.1", port=5000)