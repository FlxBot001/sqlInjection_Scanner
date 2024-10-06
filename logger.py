import logging
from colorama import Fore, Style
from config import LOG_FILE, LOG_LEVEL

def setup_logging():
    """Sets up the logging configuration."""
    logging.basicConfig(filename=LOG_FILE, level=logging.getLevelName(LOG_LEVEL), format="%(asctime)s - %(message)s")

def log_results(message):
    """Logs the results to a log file."""
    logging.info(message)

def print_status(message, color='white'):
    """Prints the status with color formatting."""
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'white': Fore.WHITE
    }
    print(f"{color_map.get(color, Fore.WHITE)}{message}{Style.RESET_ALL}")
