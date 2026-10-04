import os

# =====================
# Path Configuration
# =====================
PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

# Throwaway Chrome profile used by the browser transport. Kept outside the
# repo and outside the user's real Chrome profile so the two never collide.
# It holds live O'Reilly session cookies, so it lives under the user's home
# (not world-readable /tmp); launch_chrome_with_debugging() forces it to 0700.
CHROME_PROFILE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "safaribooks", "chrome_profile")

# =====================
# Host & URL Constants
# =====================
ORLY_BASE_HOST   = "oreilly.com"  # Main O'Reilly domain
SAFARI_BASE_HOST = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST  = f"api.{ORLY_BASE_HOST}"

SAFARI_BASE_URL  = f"https://{SAFARI_BASE_HOST}"
