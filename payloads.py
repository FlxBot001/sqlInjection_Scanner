import random
from config import DEFAULT_PAYLOADS

def generate_ai_payload():
    """Generates a random SQL injection payload."""
    return random.choice(DEFAULT_PAYLOADS)
