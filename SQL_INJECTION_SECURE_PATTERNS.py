"""
SQL_INJECTION_SECURE_PATTERNS.py

This file demonstrates SECURE vs INSECURE patterns for database queries.
Use this as a reference when writing database code.

Key Rule: NEVER use f-strings, format(), or string concatenation for SQL queries.
         ALWAYS use parameterized queries with ? placeholders.
"""

import sqlite3

DB_PATH = "database.db"


# ============================================================================
# ❌ INSECURE PATTERNS - DO NOT USE
# ============================================================================

def insecure_login(username, password):
    """
    INSECURE: Uses f-string to build SQL query.
    
    Attack: username = "admin' --"
    Results in: SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
    The -- comments out the password check!
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ❌ DANGEROUS - DO NOT DO THIS
    cur.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
    user = cur.fetchone()
    con.close()
    return user


def insecure_search(search_term):
    """
    INSECURE: Uses string format() to build SQL query.
    
    Attack: search_term = "'; DELETE FROM posts; --"
    Results in: SELECT * FROM posts WHERE title LIKE '%'; DELETE FROM posts; --%'
    The attacker can delete all posts!
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ❌ DANGEROUS - DO NOT DO THIS
    query = "SELECT * FROM posts WHERE title LIKE '%{}%'".format(search_term)
    cur.execute(query)
    posts = cur.fetchall()
    con.close()
    return posts


def insecure_create_post(author, content):
    """
    INSECURE: Uses string concatenation (+) to build SQL query.
    
    Attack: content = "'); DROP TABLE posts; --"
    Results in: INSERT INTO posts (author, content) VALUES (...); DROP TABLE posts; --)
    The attacker can drop the entire posts table!
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ❌ DANGEROUS - DO NOT DO THIS
    query = "INSERT INTO posts (author, content) VALUES ('" + author + "', '" + content + "')"
    cur.execute(query)
    con.commit()
    con.close()


# ============================================================================
# ✅ SECURE PATTERNS - USE THESE
# ============================================================================

def secure_login(username, password):
    """
    SECURE: Uses parameterized query with ? placeholders.
    
    Benefit: Database driver treats parameters as DATA, not executable code.
    Even if user enters: admin' --
    It will look for a username literally equal to: admin' --
    This username won't exist, so login fails safely.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    user = cur.fetchone()
    con.close()
    return user


def secure_search(search_term):
    """
    SECURE: Uses parameterized query with named parameter.
    
    The search_term is treated as a literal string value, not SQL code.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query
    # Note: LIKE needs wildcards in the data value, not the SQL
    safe_search = f"%{search_term}%"
    cur.execute(
        "SELECT * FROM posts WHERE title LIKE ?",
        (safe_search,)
    )
    posts = cur.fetchall()
    con.close()
    return posts


def secure_create_post(author, content):
    """
    SECURE: Uses parameterized query with multiple parameters.
    
    Both author and content are safely passed as parameters,
    never as part of the SQL structure.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query with multiple placeholders
    cur.execute(
        "INSERT INTO posts (author, content) VALUES (?, ?)",
        (author, content)
    )
    con.commit()
    con.close()


def secure_get_user_profile(username):
    """
    SECURE: Parameterized query for SELECT with single parameter.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query
    cur.execute(
        "SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()
    con.close()
    return row


def secure_send_message(sender, recipient, body):
    """
    SECURE: Parameterized query with multiple parameters.
    
    All three user-provided values are safely parameterized.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query with multiple parameters
    cur.execute(
        "INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)",
        (sender, recipient, body)
    )
    con.commit()
    con.close()


def secure_update_user(username, new_bio):
    """
    SECURE: UPDATE query with parameters.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    # ✅ SAFE - Uses parameterized query
    cur.execute(
        "UPDATE users SET bio = ? WHERE username = ?",
        (new_bio, username)
    )
    con.commit()
    con.close()


def secure_bulk_operation(user_ids):
    """
    SECURE: Handling multiple values in IN clause.
    
    For a dynamic number of parameters, create placeholders dynamically.
    """
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    
    # Create placeholders: ? ? ? for [1, 2, 3]
    placeholders = ','.join(['?' for _ in user_ids])
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"
    
    # ✅ SAFE - User IDs are passed as parameters, not in SQL string
    cur.execute(query, user_ids)
    users = cur.fetchall()
    con.close()
    return users


# ============================================================================
# COMPARISON TABLE
# ============================================================================
"""
┌─────────────────────┬──────────────────────────────┬─────────────────────┐
│      Method         │         Code Pattern         │     Vulnerability   │
├─────────────────────┼──────────────────────────────┼─────────────────────┤
│ ❌ f-string         │ f"...WHERE id = '{id}'"      │ SQL INJECTION       │
│ ❌ format()         │ "...WHERE id = '{}'".format()│ SQL INJECTION       │
│ ❌ Concatenation (+)│ "...WHERE id = '" + id + "'" │ SQL INJECTION       │
│ ❌ % formatting     │ "...WHERE id = '%s'" % id    │ SQL INJECTION       │
│                     │                              │                     │
│ ✅ ? placeholders   │ "...WHERE id = ?", (id,)     │ SAFE - RECOMMENDED  │
│ ✅ :name parameters │ "...WHERE id = :id", {...}   │ SAFE - ALTERNATIVE  │
│ ✅ ORM (SQLAlchemy) │ Model.query.filter_by(id=id) │ SAFE - AUTOMATIC    │
└─────────────────────┴──────────────────────────────┴─────────────────────┘
"""


if __name__ == "__main__":
    print("=" * 70)
    print("SQL INJECTION SECURE PATTERNS REFERENCE")
    print("=" * 70)
    print("\n✅ SECURE FUNCTIONS in this module:")
    print("  - secure_login()")
    print("  - secure_search()")
    print("  - secure_create_post()")
    print("  - secure_get_user_profile()")
    print("  - secure_send_message()")
    print("  - secure_update_user()")
    print("  - secure_bulk_operation()")
    print("\n❌ INSECURE FUNCTIONS (for reference, DO NOT USE):")
    print("  - insecure_login()")
    print("  - insecure_search()")
    print("  - insecure_create_post()")
    print("\n" + "=" * 70)
    print("KEY RULE: Use 'cur.execute(sql_query, parameters_tuple)'")
    print("NEVER concatenate user input into SQL strings!")
    print("=" * 70)
