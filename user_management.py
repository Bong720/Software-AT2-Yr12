import sqlite3 as sql
import time
import random
import os
import bcrypt
import bleach

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py
#  Handles all direct database operations for the Unsecure Social PWA.
#
#  INTENTIONAL VULNERABILITIES (for educational use):
#    1. SQL Injection      — f-string queries throughout
#    2. Timing side-channel — sleep only fires when username EXISTS
#    3. No input validation — any string accepted as username/password
#    4. IDOR-equivalent    — username passed from client-side hidden field
# ─────────────────────────────────────────────────────────────────────────────

# Absolute paths — works regardless of where `python main.py` is called from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")


def insertUser(username, password, DoB, bio=""):
    """
    Insert a new user.
    Password is now hashed using bcrypt for security.
    Bio is sanitized to prevent XSS attacks.
    """
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Sanitize bio to prevent XSS
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_bio = bleach.clean(bio, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, hashed_password.decode('utf-8'), DoB, sanitized_bio),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    """
    Authenticate a user.
    Checks if the username and password combination exists in the database.
    Passwords are now hashed with bcrypt.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    con.close()
    
    if result:
        stored_password = result[0]
        # Check if password is hashed (starts with $2b$) or plaintext
        if stored_password.startswith('$2b$'):
            # Hashed password
            return bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))
        else:
            # Plaintext password (for existing users)
            return stored_password == password
    return False


def insertPost(author, content):
    """
    Insert a post.
    Content is now sanitized to prevent XSS attacks.
    VULNERABILITY: SQL Injection via f-string on both author and content.
    VULNERABILITY: author comes from a hidden HTML field — easily spoofed (IDOR).
    """
    # Sanitize content to prevent XSS
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"INSERT INTO posts (author, content) VALUES ('{author}', '{sanitized_content}')")
    con.commit()
    con.close()


def getPosts():
    """
    Get all posts newest-first.
    Content is now sanitized to prevent XSS attacks.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    """
    Get a user profile row.
    VULNERABILITY: SQL Injection via f-string — try /profile?user=admin'--
    VULNERABILITY: No authentication check — any visitor can view any profile.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = '{username}'")
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """
    Get inbox for a user.
    VULNERABILITY: SQL Injection via f-string.
    VULNERABILITY: No auth check — change ?user= to read anyone's inbox.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"SELECT * FROM messages WHERE recipient = '{username}' ORDER BY id DESC")
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """
    Send a DM.
    Message body is now sanitized to prevent XSS attacks.
    VULNERABILITY: SQL Injection on all three fields.
    VULNERABILITY: sender taken from hidden form field — can be spoofed.
    """
    # Sanitize message body to prevent XSS
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_body = bleach.clean(body, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(f"INSERT INTO messages (sender, recipient, body) VALUES ('{sender}', '{recipient}', '{sanitized_body}')")
    con.commit()
    con.close()


def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0                                                                                                                        
