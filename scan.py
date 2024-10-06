import requests
from urllib.parse import urljoin
import concurrent.futures
from forms import get_forms, form_details, vulnerable
from payloads import generate_ai_payload
from logger import setup_logging, log_results, print_status
from config import USER_AGENT
import validators  # Use validators library for URL validation
from colorama import Fore, Style
import time
import random
import string
from report import generate_report  # Import the report generation function

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

# Instance management
instances = {}
MIN_INSTANCES = 2
MAX_INSTANCES = 4

# Global variable to store vulnerabilities summary
vulnerabilities_summary = {}

def generate_instance_key():
    """Generates a random string key for an instance."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def initialize_instances(count=MIN_INSTANCES):
    """Initializes a specified number of instances."""
    for _ in range(count):
        key = generate_instance_key()
        instances[key] = None  # Placeholder for the actual instance
        time.sleep(0.5)  # Simulating initialization delay

def display_active_instances():
    """Displays the current active instances."""
    print(f"\n[+] Active Instances: {len(instances)} | Instances: {', '.join(instances.keys())}")

def display_banner():
    banner = f"""{Fore.RED}
     ____  _    _   _____  _    _  ______ _   _ _   _  ____  _  __   ___  ____   _____ 
    / __ \| |  | | |_   _| | |  | |/ __ \ | | | \ | |  _ \| |/ /  / _ \|  _ \ / ____| 
   | |  | | |  | |   | |   | |  | | |  | | | | |  \| | |_) | ' /  | | | | |_) | (___  
   | |  | | |  | |   | |   | |  | | |  | | | | | . ` |  _ <|  <   | | | |  _ < \___ \ 
   | |__| | |__| |  _| |_  | |__| | |__| | |_| | |\  | |_) | . \  | |_| | |_) |____) |
    \____/ \____/  |_____|  \____/ \____/ \___/|_| \_|____/|_|\_\  \___/|_____/_____/
                                                                                     

                  SQL Injection Vulnerability Scanner
                  Developed by 10kartik
                  A tool to help identify potential SQL injection vulnerabilities in web applications.
                  Use responsibly and ethically.
    {Style.RESET_ALL}
    """
    
    # Print the banner
    print(banner)
    time.sleep(2)  # Wait for 2 seconds before continuing

def is_valid_url(url):
    """Validate the provided URL."""
    return validators.url(url)

def scan_form(form, url, scan_type, instance_key):
    """Tests a single form for SQL injection vulnerabilities."""
    form_info = form_details(form)
    action = form_info["action"]
    post_url = urljoin(url, action)
    method = form_info["method"]

    print(f"[+] [Instance: {instance_key}] Testing form action: {post_url} (Method: {method}) - Scan Type: {scan_type}")
    
    # Initialize vulnerabilities list for the form
    vulnerabilities = []

    # Try different payloads to detect SQL injection vulnerabilities
    for _ in range(3):
        payload = generate_ai_payload()
        # Create data dictionary for form submission
        data = {input_tag["name"]: payload for input_tag in form_info["inputs"] if input_tag["type"] != "submit"}
        
        # Send the modified form data based on the form method
        try:
            if method.lower() == "post":
                response = session.post(post_url, data=data)
            else:
                response = session.get(post_url, params=data)

            if vulnerable(response):
                print_status(f"[!] [Instance: {instance_key}] SQL Injection vulnerability detected on {post_url} with payload: {payload}", color='red')
                log_results(f"Vulnerable form found at {post_url} with payload: {payload}")
                vulnerabilities.append(f"Vulnerable with payload: {payload}")
                break
            else:
                print_status(f"[-] [Instance: {instance_key}] No SQL Injection vulnerability detected on {post_url} with payload: {payload}", color='green')
        except requests.exceptions.RequestException as e:
            print_status(f"[!] [Instance: {instance_key}] Request error on {post_url}: {e}", color='yellow')

    # Add the vulnerabilities for the form to the global summary
    if vulnerabilities:
        vulnerabilities_summary[form_info["action"]] = vulnerabilities

def sql_injection_scan(url, scan_type):
    """Scans a given URL for SQL injection vulnerabilities."""
    forms = get_forms(session, url)  # Pass the session to the get_forms function
    print(f"[+] Detected {len(forms)} forms on {url}.")
    
    # Use concurrent threads to speed up the scan
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for instance_key in instances.keys():
            for form in forms:
                futures.append(executor.submit(scan_form, form, url, scan_type, instance_key))
        
        for future in concurrent.futures.as_completed(futures):
            future.result()

    # After completing the scan, generate the report
    report_filename = f"scan_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_report(report_filename, vulnerabilities_summary)  # Call the report generation function
    print(f"[+] Scan report saved as {report_filename}")

def help_manual():
    """Displays the help manual for operational commands."""
    print(f"{Fore.GREEN}\nOperational Commands Manual:")
    print("1. Perform SQL Injection Scan")
    print("2. Help")
    print("3. Quit")
    print(f"{Style.RESET_ALL}")

def scale_up_instances():
    """Scales up the number of instances to the maximum allowed."""
    current_count = len(instances)
    if current_count < MAX_INSTANCES:
        additional_count = min(MAX_INSTANCES - current_count, MAX_INSTANCES - MIN_INSTANCES)
        initialize_instances(additional_count)
        display_active_instances()
    else:
        print("[!] Maximum number of instances already active.")

def scale_down_instances():
    """Scales down the number of instances to the minimum allowed."""
    current_count = len(instances)
    if current_count > MIN_INSTANCES:
        instance_to_remove = random.choice(list(instances.keys()))
        del instances[instance_to_remove]
        print(f"[+] Killed instance: {instance_to_remove}")
        display_active_instances()
    else:
        print("[!] Minimum number of instances active; cannot scale down.")

def kill_instance(instance_key):
    """Terminates a specific instance.""" 
    if instance_key in instances:
        del instances[instance_key]
        print(f"[+] Killed instance: {instance_key}")
        display_active_instances()
    else:
        print("[!] Instance not found.")

def main_menu():
    """Displays the main menu and handles user input."""
    display_banner()  # Show the banner
    initialize_instances()  # Initialize instances
    display_active_instances()  # Show active instances

    while True:
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print("1. Perform SQL Injection Scan")
        print("2. Help")
        print("3. Quit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            # Step 1: Select Scan Type
            while True:
                print(f"\n{Fore.CYAN}Select Scan Type:{Style.RESET_ALL}")
                for key, value in SCAN_TYPES.items():
                    print(f"{key}: {value}")
                scan_type_choice = input("Enter your choice (1-10): ")
                if scan_type_choice in SCAN_TYPES:
                    selected_scan_type = SCAN_TYPES[scan_type_choice]
                    print(f"[+] Selected Scan Type: {selected_scan_type}")
                    break
                else:
                    print("[!] Invalid choice for scan type.")
            
            # Step 2: Select Protocol
            while True:
                print(f"\n{Fore.CYAN}Select Protocol:{Style.RESET_ALL}")
                protocol = input("Select protocol (HTTP/HTTPS): ").upper()
                if protocol in ["HTTP", "HTTPS"]:
                    print(f"[+] Selected Protocol: {protocol}")
                    break
                else:
                    print("[!] Invalid choice for protocol.")

            # Step 3: Input Address
            while True:
                url_to_check = input("Enter the URL to check for SQL injection vulnerabilities: ")
                if is_valid_url(url_to_check):
                    print(f"[+] Valid URL: {url_to_check}")
                    break
                else:
                    print("[!] Invalid URL. Please enter a valid URL.")

            # Step 4: Select Payload or All
            while True:
                payload_choice = input("Select Payload or All (1: Payload, 2: All): ")
                if payload_choice in ["1", "2"]:
                    print(f"[+] Selected Payload Option: {payload_choice}")
                    break
                else:
                    print("[!] Invalid choice for payload.")

            # Step 5: Select number of instances
            while True:
                instances_choice = input("Select number of instances (2-4): ")
                if instances_choice.isdigit() and MIN_INSTANCES <= int(instances_choice) <= MAX_INSTANCES:
                    instances.clear()  # Clear existing instances
                    initialize_instances(int(instances_choice))
                    display_active_instances()
                    break
                else:
                    print("[!] Invalid number of instances. Must be between 2 and 4.")

            # Start SQL Injection scan
            sql_injection_scan(url_to_check, selected_scan_type)

        elif choice == '2':
            help_manual()

        elif choice == '3':
            print("[+] Exiting the application.")
            break

        else:
            print("[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()  # Run the main menu
