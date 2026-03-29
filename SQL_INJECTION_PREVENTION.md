# SQL Injection Prevention Guide

## What is SQL Injection?

SQL Injection is a code injection technique where an attacker inserts malicious SQL code into input fields to manipulate database queries and gain unauthorized access to data or perform unintended operations.

### Example Attack

**Vulnerable Code:**
```python
username = request.args.get('user')
cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

**Attack Input:**
```
?user=admin' OR '1'='1
```

**Resulting SQL:**
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
```

This query returns ALL users because `'1'='1'` is always true.

---

## Prevention Methods

### ✅ **METHOD 1: Parameterized Queries (RECOMMENDED)**

Use placeholders (`?`) instead of string concatenation:

```python
# SECURE - Uses parameterized query
username = request.args.get('user')
cur.execute("SELECT * FROM users WHERE username = ?", (username,))

# Works with multiple parameters
cur.execute(
    "INSERT INTO posts (author, content) VALUES (?, ?)",
    (author, content)
)
```

**Why it works:** The database driver treats the parameter values as data, never as executable code.

---

### ✅ **METHOD 2: ORM (Object-Relational Mapping)**

Use SQLAlchemy or Django ORM which handle parameterization automatically:

```python
# Using SQLAlchemy
from sqlalchemy import create_engine, text

engine = create_engine('sqlite:///database.db')
with engine.connect() as conn:
    query = text("SELECT * FROM users WHERE username = :username")
    result = conn.execute(query, {"username": username})

# Or with SQLAlchemy ORM
user = User.query.filter_by(username=username).first()
```

---

## Fixed Code in This Project

All vulnerable functions have been updated to use parameterized queries:

### Fixed `insertPost()`
```python
def insertPost(author, content):
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # Parameterized query prevents SQL injection
    cur.execute("INSERT INTO posts (author, content) VALUES (?, ?)", 
                (author, sanitized_content))
    con.commit()
    con.close()
```

### Fixed `getUserProfile()`
```python
def getUserProfile(username):
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # Parameterized query prevents SQL injection
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", 
                (username,))
    row = cur.fetchone()
    con.close()
    return row
```

### Fixed `getMessages()`
```python
def getMessages(username):
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # Parameterized query prevents SQL injection
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", 
                (username,))
    rows = cur.fetchall()
    con.close()
    return rows
```

### Fixed `sendMessage()`
```python
def sendMessage(sender, recipient, body):
    sanitized_body = bleach.clean(body, tags=[], strip=True)
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    # Parameterized query prevents SQL injection
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)", 
                (sender, recipient, sanitized_body))
    con.commit()
    con.close()
```

---

## Best Practices Checklist

- ✅ **Always use parameterized queries** with `?` placeholders for SQLite
- ✅ **Never concatenate user input** into SQL strings (no f-strings or format())
- ✅ **Validate and sanitize input** for XSS (using bleach library as done here)
- ✅ **Use principle of least privilege** - database user should have minimal permissions
- ✅ **Enable SQL error suppression** in production (don't expose database errors to users)
- ✅ **Use prepared statements** - they separate SQL code from data
- ✅ **Input validation** - check expected format, length, type
- ✅ **Security testing** - regularly test for injection vulnerabilities

---

## Testing for SQL Injection

### Common Test Payloads

```
' OR '1'='1
' OR 1=1 --
admin' --
' UNION SELECT * FROM users --
'; DROP TABLE users; --
```

### How to Test
1. Go to `/profile?user=` endpoint
2. Try: `admin' OR '1'='1`
3. With **vulnerable code**: Would return all users
4. With **fixed code**: Would find no user (literal username lookup)

---

## Additional Security Headers

Consider adding these headers to prevent SQL injection chains:

```python
# In main.py Flask routes
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

---

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLite Prepared Statements](https://www.sqlite.org/appfunc.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [NIST Database Security](https://csrc.nist.gov/publications/detail/sp/800-92/final)

---

## Summary

All SQL injection vulnerabilities in `user_management.py` have been **FIXED** by replacing:
- ❌ f-string queries: `f"SELECT * FROM users WHERE username = '{username}'"`
- ✅ Parameterized queries: `"SELECT * FROM users WHERE username = ?", (username,)`

This ensures user input is treated as **data**, never as executable SQL code.
