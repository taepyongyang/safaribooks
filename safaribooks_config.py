import os
import re
import safaribooks

# =====================
# Path Configuration
# =====================
PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

# =====================
# Host & URL Constants
# =====================
ORLY_BASE_HOST   = "oreilly.com"  # Main O'Reilly domain
SAFARI_BASE_HOST = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST  = f"api.{ORLY_BASE_HOST}"

ORLY_BASE_URL    = f"https://www.{ORLY_BASE_HOST}"
SAFARI_BASE_URL  = f"https://{SAFARI_BASE_HOST}"
API_ORIGIN_URL   = f"https://{API_ORIGIN_HOST}"
PROFILE_URL      = f"{SAFARI_BASE_URL}/profile/"

# =====================
# API Endpoints
# =====================
REGISTER_URL  = f"{SAFARI_BASE_URL}/register/"
CHECK_EMAIL   = f"{SAFARI_BASE_URL}/check-email-availability/"
CHECK_PWD     = f"{SAFARI_BASE_URL}/check-password/"

# =====================
# Regex Patterns
# =====================
CSRF_TOKEN_RE = re.compile(r"(?<=name='csrfmiddlewaretoken' value=')([^']+)")

# =====================
# Debug/Proxy Settings
# =====================
USE_PROXY = False
PROXIES   = {"https": "https://127.0.0.1:8080"}
