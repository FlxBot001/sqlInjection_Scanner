import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Set a custom User-Agent header to mimic a real browser
USER_AGENT = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Initialize a requests session with custom headers
session = requests.Session()
session.headers["User-Agent"] = USER_AGENT

def get_forms(url):
    """
    Extracts HTML forms from a given URL.

    Parameters:
    - url (str): The URL from which to extract HTML forms.

    Returns:
    - list: A list of HTML form elements.
    """
    # Send a GET request to the URL and parse the HTML content
    response = session.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    # Find all form elements in the parsed HTML
    return soup.find_all("form")

def form_details(form):
    """
    Extracts details of a form including action, method, and inputs.

    Parameters:
    - form (BeautifulSoup Tag): The HTML form element.

    Returns:
    - dict: A dictionary containing form details.
    """
    details = {}
    # Extract action and method attributes of the form
    details['action'] = form.attrs.get("action")
    details['method'] = form.attrs.get("method", "get")
    details['inputs'] = []
    # Extract details of each input field within the form
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        # Append input details to the inputs list
        details['inputs'].append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    return details

def vulnerable(response):
    """
    Checks if the response indicates potential SQL injection vulnerabilities.

    Parameters:
    - response (requests Response): The HTTP response object.

    Returns:
    - bool: True if potential vulnerability detected, False otherwise.
    """
    # Define a set of common error messages indicating SQL injection vulnerabilities
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax"
    }
    # Check if any of the error messages are present in the response content
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def sql_injection_scan(url):
    """
    Scans a given URL for SQL injection vulnerabilities.

    Parameters:
    - url (str): The URL to be scanned for vulnerabilities.
    """
    # Extract forms from the given URL
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    # Iterate through each form found
    for form in forms:
        # Extract details of the current form
        form_details_info = form_details(form)
        # Try different payloads to detect SQL injection vulnerabilities
        for i in "\"'":
            data = {}
            # Modify input values with payloads
            for input_tag in form_details_info["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"
            # Send the modified form data based on the form method
            if form_details_info["method"] == "post": 
                response = session.post(url, data=data)
            elif form_details_info["method"] == "get":
                response = session.get(url, params=data)
            # Check if the response indicates a vulnerability
            if vulnerable(response):
                print("SQL injection attack vulnerability in link:", url)
                # If a vulnerability is detected, you might want to log it for further analysis.
                # logging.info(f"SQL injection vulnerability detected in {url}")
                break
            else:
                print("No SQL injection attack vulnerability detected in link:", url)
                # If no vulnerability is detected, you might want to log it.
                # logging.info(f"No SQL injection vulnerability detected in {url}")
                break

if __name__ == "__main__":
    # URL to be checked for SQL injection vulnerabilities
    url_to_check = "https://google.com"
    # Initiate SQL injection scan for the specified URL
    sql_injection_scan(url_to_check)
