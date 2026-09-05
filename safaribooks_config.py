import os

# =====================
# Path Configuration
# =====================
PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

# Throwaway Chrome profile used by the browser transport. Kept outside the
# repo and outside the user's real Chrome profile so the two never collide.
CHROME_PROFILE_DIR = "/tmp/safaribooks_chrome_profile"

# =====================
# Host & URL Constants
# =====================
ORLY_BASE_HOST   = "oreilly.com"  # Main O'Reilly domain
SAFARI_BASE_HOST = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST  = f"api.{ORLY_BASE_HOST}"

SAFARI_BASE_URL  = f"https://{SAFARI_BASE_HOST}"
