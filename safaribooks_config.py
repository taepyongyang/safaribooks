import os

# Paths
PATH         = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

# Base hosts
ORLY_BASE_HOST    = "oreilly.com"  # Main O'Reilly domain
SAFARI_BASE_HOST  = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST   = f"api.{ORLY_BASE_HOST}"

# Base URLs
ORLY_BASE_URL     = f"https://www.{ORLY_BASE_HOST}"
SAFARI_BASE_URL   = f"https://{SAFARI_BASE_HOST}"
API_ORIGIN_URL    = f"https://{API_ORIGIN_HOST}"
PROFILE_URL       = f"{SAFARI_BASE_URL}/profile/"

# Debug/Proxy settings
USE_PROXY = False
PROXIES   = {"https": "https://127.0.0.1:8080"}
