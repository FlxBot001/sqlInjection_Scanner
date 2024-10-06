import requests
from urllib.parse import urljoin
import concurrent.futures
from forms import get_forms, form_details, vulnerable
from payloads import generate_ai_payload
from logger import setup_logging, log_results, print_status
from config import USER_AGENT

# Configure logging for detailed scan results
setup_logging()

# Initialize a requests session with a custom User-Agent
session = requests.Session()
session.headers["User-Agent"] = USER_AGENT

# Available scan types
SCAN_TYPES = {
    '1': 'Error-Based SQL Injection',
    '2': 'Union-Based SQL Injection',
    '3': 'Blind SQL Injection',
    '4': 'Time-Based SQL Injection',
    '5': 'Out-of-Band SQL Injection',
    '6': 'Second-Order SQL Injection',
    '7': 'Stored Procedures Injection',
    '8': 'Blind Injection with Conditional Responses',
    '9': 'Cross-Site Scripting via SQL Injection',
    '10': 'Automated Scanning with Fuzzing Techniques'
}

def scan_form(form, url, scan_type):
    """Tests a single form for SQL injection vulnerabilities."""
    form_info = form_details(form)
    action = form_info["action"]
    post_url = urljoin(url, action)
    method = form_info["method"]

    print(f"[+] Testing form action: {post_url} (Method: {method}) - Scan Type: {scan_type}")
    
    # Try different payloads to detect SQL injection vulnerabilities
    for _ in range(3):
        payload = generate_ai_payload()  # This can be further customized based on scan_type
        # Create data dictionary for form submission
        data = {input_tag["name"]: payload for input_tag in form_info["inputs"] if input_tag["type"] != "submit"}
        
        # Send the modified form data based on the form method
        try:
            if method == "post":
                response = session.post(post_url, data=data)
            else:
                response = session.get(post_url, params=data)

            if vulnerable(response):
                print_status(f"[!] SQL Injection vulnerability detected on {post_url} with payload: {payload}", color='red')
                log_results(f"Vulnerable form found at {post_url} with payload: {payload}")
                break
            else:
                print_status(f"[-] No SQL Injection vulnerability detected on {post_url} with payload: {payload}", color='green')
        except requests.exceptions.RequestException as e:
            print_status(f"[!] Request error on {post_url}: {e}", color='yellow')

def sql_injection_scan(url, scan_type):
    """Scans a given URL for SQL injection vulnerabilities."""
    forms = get_forms(session, url)  # Pass the session to the get_forms function
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    # Use concurrent threads to speed up the scan
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_form, form, url, scan_type) for form in forms]
        
        for future in concurrent.futures.as_completed(futures):
            future.result()

if __name__ == "__main__":
    print("Select the type of SQL injection scan:")
    for key, value in SCAN_TYPES.items():
        print(f"{key}: {value}")
        
    scan_choice = input("Enter your choice (1-10): ")
    if scan_choice not in SCAN_TYPES:
        print("[!] Invalid choice. Defaulting to Error-Based SQL Injection.")
        scan_choice = '1'
    
    url_to_check = input("Enter the URL to check for SQL injection vulnerabilities: ")
    sql_injection_scan(url_to_check, SCAN_TYPES[scan_choice])
