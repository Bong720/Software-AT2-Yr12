"""
SQL_INJECTION_TEST_CASES.py

Demonstrates attack payloads and how parameterized queries prevent them.
This is for educational purposes to understand SQL injection risks.

IMPORTANT: These attacks would work on the INSECURE version only.
The FIXED version (using parameterized queries) is immune to these attacks.
"""


# ============================================================================
# COMMON SQL INJECTION ATTACK PAYLOADS
# ============================================================================

ATTACK_PAYLOADS = {
    "Authentication Bypass": [
        "admin' --",                          # Comment out password check
        "' OR '1'='1",                       # Always true condition
        "admin' OR '1'='1' --",              # Admin login without password
        "' OR 1=1 --",                       # Numeric version
    ],
    
    "Data Exfiltration": [
        "' UNION SELECT username, password FROM users --",
        "' UNION SELECT id, username, password, 4, 5 FROM users --",
        "' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES --",
    ],
    
    "Data Modification": [
        "'; UPDATE users SET role='admin' WHERE username='attacker' --",
        "'; INSERT INTO users VALUES ('hacker', 'password123') --",
        "'; DELETE FROM posts WHERE author='victim' --",
    ],
    
    "Table Destruction": [
        "'; DROP TABLE users; --",
        "'; DROP TABLE posts; DROP TABLE messages; --",
        "admin'; TRUNCATE TABLE logs; --",
    ],
    
    "Advanced Techniques": [
        "' AND SLEEP(5) --",                 # Time-based SQL injection
        "' AND 1=(SELECT COUNT(*) FROM users) --",  # Stacked queries
        "1' UNION SELECT NULL,version(),NULL --",   # Database fingerprinting
    ],
}


# ============================================================================
# VULNERABLE vs SECURE EXAMPLES
# ============================================================================

class VulnerableQueryExample:
    """Shows how attacks work on vulnerable code"""
    
    @staticmethod
    def vulnerable_profile_lookup(username):
        """
        VULNERABLE CODE:
        cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
        
        ATTACK: username = "admin' --"
        RESULT: SELECT * FROM users WHERE username = 'admin' --'
        EFFECT: Returns admin's profile without proper authorization
        """
        sql = f"SELECT * FROM users WHERE username = '{username}'"
        return f"EXECUTED: {sql}"
    
    @staticmethod
    def vulnerable_login(username, password):
        """
        VULNERABLE CODE:
        cur.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        
        ATTACK: username = "admin' --", password = "anything"
        RESULT: SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
        EFFECT: Password check is bypassed! Attacker logs in as admin without knowing password.
        """
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        return f"EXECUTED: {sql}"
    
    @staticmethod
    def vulnerable_search(search_term):
        """
        VULNERABLE CODE:
        cur.execute(f"SELECT * FROM posts WHERE content LIKE '%{search_term}%'")
        
        ATTACK: search_term = "%' OR '1'='1' --"
        RESULT: SELECT * FROM posts WHERE content LIKE '%%' OR '1'='1' --'%'
        EFFECT: Returns ALL posts because '1'='1' is always true
        """
        sql = f"SELECT * FROM posts WHERE content LIKE '%{search_term}%'"
        return f"EXECUTED: {sql}"


class SecureQueryExample:
    """Shows how parameterized queries prevent attacks"""
    
    @staticmethod
    def secure_profile_lookup(username):
        """
        SECURE CODE:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        
        ATTACK: username = "admin' --"
        RESULT: Database looks for user with LITERAL username: admin' --
        EFFECT: No such user exists, returns None safely
        """
        # Instead of showing SQL, we show what parameters are passed
        return f"SQL: SELECT * FROM users WHERE username = ?\nPARAM: {username}"
    
    @staticmethod
    def secure_login(username, password):
        """
        SECURE CODE:
        cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                    (username, password))
        
        ATTACK: username = "admin' --", password = "anything"
        RESULT: Database looks for user with username = "admin' --" literally
        EFFECT: No such user exists, login fails safely
        """
        return f"SQL: SELECT * FROM users WHERE username = ? AND password = ?\nPARAMS: ({username}, {password})"
    
    @staticmethod
    def secure_search(search_term):
        """
        SECURE CODE:
        cur.execute("SELECT * FROM posts WHERE content LIKE ?", (f"%{search_term}%",))
        
        ATTACK: search_term = "%' OR '1'='1' --"
        RESULT: Database searches for content matching: %%' OR '1'='1' --% literally
        EFFECT: Finds nothing because that exact pattern doesn't exist
        """
        safe_param = f"%{search_term}%"
        return f"SQL: SELECT * FROM posts WHERE content LIKE ?\nPARAM: {safe_param}"


# ============================================================================
# DEMONSTRATION
# ============================================================================

def demonstrate_attack_scenarios():
    """Shows concrete examples of attacks and defenses"""
    
    print("=" * 80)
    print("SQL INJECTION ATTACK SCENARIOS & DEFENSE")
    print("=" * 80)
    
    scenarios = [
        {
            "name": "Authentication Bypass Attack",
            "attack": "admin' --",
            "vulnerable": VulnerableQueryExample.vulnerable_login("admin' --", "anything"),
            "secure": SecureQueryExample.secure_login("admin' --", "anything"),
            "impact": "Attacker logs into admin account WITHOUT knowing password"
        },
        {
            "name": "Post-Authentication Privilege Escalation",
            "attack": "'; UPDATE users SET role='admin' WHERE username='attacker' --",
            "vulnerable": VulnerableQueryExample.vulnerable_search("'; UPDATE users SET role='admin' WHERE username='attacker' --"),
            "secure": SecureQueryExample.secure_search("'; UPDATE users SET role='admin' WHERE username='attacker' --"),
            "impact": "Attacker grants themselves admin privileges"
        },
        {
            "name": "Data Exfiltration via UNION",
            "attack": "' UNION SELECT username, password FROM users --",
            "vulnerable": VulnerableQueryExample.vulnerable_search("' UNION SELECT username, password FROM users --"),
            "secure": SecureQueryExample.secure_search("' UNION SELECT username, password FROM users --"),
            "impact": "Attacker retrieves all usernames and passwords"
        },
        {
            "name": "Table Destruction (Catastrophic)",
            "attack": "'; DROP TABLE posts; --",
            "vulnerable": VulnerableQueryExample.vulnerable_search("'; DROP TABLE posts; --"),
            "secure": SecureQueryExample.secure_search("'; DROP TABLE posts; --"),
            "impact": "Entire posts table is deleted — data loss!"
        },
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\nSCENARIO {i}: {scenario['name']}")
        print("-" * 80)
        print(f"Attack Payload: {scenario['attack']}")
        print(f"\nVULNERABLE CODE:")
        print(f"  {scenario['vulnerable']}")
        print(f"\nSECURE CODE:")
        print(f"  {scenario['secure']}")
        print(f"\nIMPACT IF VULNERABLE: {scenario['impact']}")
        print(f"PROTECTION WITH FIX: ✅ Attack fails safely")


def show_payload_categories():
    """Shows categorized attack payloads"""
    
    print("\n" + "=" * 80)
    print("CATEGORIZED ATTACK PAYLOADS (FOR REFERENCE)")
    print("=" * 80)
    
    for category, payloads in ATTACK_PAYLOADS.items():
        print(f"\n{category.upper()}")
        print("-" * 80)
        for payload in payloads:
            print(f"  → {payload}")


def comparison_table():
    """Shows vulnerable vs secure comparison"""
    
    print("\n" + "=" * 80)
    print("VULNERABLE vs SECURE CODE COMPARISON")
    print("=" * 80)
    
    comparisons = [
        {
            "vulnerable": 'cur.execute(f"SELECT * FROM users WHERE username = \'{username}\'")',
            "secure": 'cur.execute("SELECT * FROM users WHERE username = ?", (username,))',
        },
        {
            "vulnerable": 'cur.execute(f"INSERT INTO posts VALUES (\\"{author}\\", \\"{content}\\")")',
            "secure": 'cur.execute("INSERT INTO posts VALUES (?, ?)", (author, content))',
        },
        {
            "vulnerable": 'query = "WHERE id = " + str(user_id)\ncur.execute(query)',
            "secure": 'cur.execute("WHERE id = ?", (user_id,))',
        },
    ]
    
    for i, comp in enumerate(comparisons, 1):
        print(f"\nExample {i}:")
        print(f"  ❌ Vulnerable:\n     {comp['vulnerable']}")
        print(f"  ✅ Secure:\n     {comp['secure']}")


if __name__ == "__main__":
    # Run demonstrations
    demonstrate_attack_scenarios()
    show_payload_categories()
    comparison_table()
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print("""
All vulnerable functions in user_management.py have been FIXED to use
parameterized queries. This makes them IMMUNE to all the attacks shown above.

KEY TAKEAWAY:
  ❌ NEVER: f"... WHERE id = '{user_input}'"
  ✅ ALWAYS: "... WHERE id = ?", (user_input,)

The ? placeholder tells SQLite that the value is DATA, not SQL code.
This is the primary defense against SQL injection attacks.
    """)
    print("=" * 80)
