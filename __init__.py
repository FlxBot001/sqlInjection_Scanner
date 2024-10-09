"""
SQL Injection Scanner Package
A Python package designed to detect SQL injection vulnerabilities in web applications.

This module contains the core functionality of the SQL Injection Scanner.
"""

__title__ = "sqlInjection_Scanner"
__description__ = "A Python program for detecting SQL injection vulnerabilities in web applications."
__version__ = "1.0.0"  # Update this version for each release
__author__ = "FlxBot"
__author_email__ = "flxnjgn@gmail.com"  # Replace with your email address
__license__ = "MIT"  # Choose an appropriate license for your project
__url__ = "https://github.com/FlxBot001/sqlInjection_Scanner"  # Replace with your project URL

from .scan import sql_injection_scan  # Importing the main scanning function
from .config import USER_AGENT  # Import any necessary configurations
from .logger import setup_logging  # Import the logging setup function
from .forms import get_forms  # Import form retrieval functionality
from .payloads import generate_ai_payload  # Import the AI payload generation function
from .report import generate_report  # Import the report generation function
from .validators import is_valid_url  # Import the URL validation function (if applicable)