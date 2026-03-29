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
#    2. Timing side-channel — FIXED: Always performs bcrypt comparison for consistent timing
#    3. No input validation — any string accepted as username/password
#    4. IDOR-equivalent    — username passed from client-side hidden field
# ─────────────────────────────────────────────────────────────────────────────

# Absolute paths — works regardless of where `python main.py` is called from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")


def username_exists(username):
    """Return True if username is already taken."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    exists = cur.fetchone() is not None
    con.close()
    return exists


def insertUser(username, password, DoB, bio=""):
    """
    Insert a new user.
    Password is now hashed using bcrypt for security.
    Bio is sanitized to prevent XSS attacks.
    Returns True on success, False on failure.
    """
    if username_exists(username):
        return False

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Sanitize bio to prevent XSS
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_bio = bleach.clean(bio, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    
    try:
        con = sql.connect(DB_PATH)
        cur = con.cursor()
        cur.execute(
            "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
            (username, hashed_password.decode('utf-8'), DoB, sanitized_bio),
        )
        con.commit()
        return True
    except sql.IntegrityError:
        return False
    finally:
        con.close()


def username_exists(username):
    """Return True if username is already registered."""
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    exists = cur.fetchone() is not None
    con.close()
    return exists


def retrieveUsers(username, password):
    """
    Authenticate a user.
    Checks if the username and password combination exists in the database.
    Passwords are hashed with bcrypt.
    TIMING ATTACK PREVENTION: Always performs bcrypt comparison regardless of user existence.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cur.fetchone()
    con.close()
    
    # TIMING ATTACK PREVENTION: Use a dummy hash if user doesn't exist
    # This ensures bcrypt comparison takes the same time regardless of username validity
    dummy_hash = bcrypt.hashpw(b'dummy_password', bcrypt.gensalt())
    
    if result:
        stored_password = result[0]
        # Check if password is hashed (starts with $2b$) or plaintext
        if stored_password.startswith('$2b$'):
            # Hashed password - use constant-time comparison
            try:
                return bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))
            except (ValueError, TypeError):
                # Invalid hash format - always return False
                return False
        else:
            # Plaintext password (legacy support) - still perform bcrypt for timing consistency
            is_match = stored_password == password
            # Perform dummy bcrypt to maintain constant timing
            bcrypt.checkpw(password.encode('utf-8'), dummy_hash)
            return is_match
    else:
        # TIMING ATTACK PREVENTION: If user not found, still perform bcrypt comparison
        # This makes the response time identical to when user exists but password is wrong
        try:
            bcrypt.checkpw(password.encode('utf-8'), dummy_hash)
        except (ValueError, TypeError):
            pass
        return False


def insertPost(author, content):
    """
    Insert a post.
    Content is now sanitized to prevent XSS attacks.
    FIXED: Uses parameterized queries (?) to prevent SQL Injection.
    VULNERABILITY: author comes from a hidden HTML field — easily spoofed (IDOR).
    """
    # Sanitize content to prevent XSS
    allowed_tags = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # FIXED: Using parameterized query with ? placeholders
    cur.execute("INSERT INTO posts (author, content) VALUES (?, ?)", (author, sanitized_content))
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
    FIXED: Uses parameterized queries (?) to prevent SQL Injection.
    VULNERABILITY: No authentication check — any visitor can view any profile.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # FIXED: Using parameterized query with ? placeholders
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    """
    Get inbox for a user.
    FIXED: Uses parameterized queries (?) to prevent SQL Injection.
    VULNERABILITY: No auth check — change ?user= to read anyone's inbox.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # FIXED: Using parameterized query with ? placeholders
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    """
    Send a DM.
    Message body is sanitized to prevent stored XSS attacks.
    No HTML tags are allowed — only plain text is stored.
    FIXED: Uses parameterized queries (?) to prevent SQL Injection.
    VULNERABILITY: sender taken from hidden form field — can be spoofed.
    """
    # Sanitize message body by stripping ALL HTML tags to prevent stored XSS
    # This is more secure than allowing specific tags
    sanitized_body = bleach.clean(body, tags=[], strip=True)
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # FIXED: Using parameterized query with ? placeholders
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)", (sender, recipient, sanitized_body))
    con.commit()
    con.close()


def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0                                                                                                                        
