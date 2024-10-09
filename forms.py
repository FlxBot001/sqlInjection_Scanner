# forms.py
import requests
from bs4 import BeautifulSoup

def get_forms(session, url):
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
    for input_tag in form.find_all(["input", "textarea", "select"]):
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
    return any(error in response.content.decode().lower() for error in errors)
