# config.py

# URLs
ORLY_BASE_HOST = "oreilly.com"
SAFARI_BASE_HOST = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST = f"api.{ORLY_BASE_HOST}"

ORLY_BASE_URL = f"https://www.{ORLY_BASE_HOST}"
SAFARI_BASE_URL = f"https://{SAFARI_BASE_HOST}"
API_ORIGIN_URL = f"https://{API_ORIGIN_HOST}"

PROFILE_URL = f"{SAFARI_BASE_URL}/profile/"
LOGIN_URL = f"{ORLY_BASE_URL}/member/auth/login/"
LOGIN_ENTRY_URL = f"{SAFARI_BASE_URL}/login/unified/?next=/home/"
API_TEMPLATE = f"{SAFARI_BASE_URL}/api/v1/book/{{0}}/"  # {0} is placeholder for bookid

REGISTER_URL = f"{SAFARI_BASE_URL}/register/"
CHECK_EMAIL_URL = f"{SAFARI_BASE_URL}/check-email-availability/"
CHECK_PWD_URL = f"{SAFARI_BASE_URL}/check-password/"

# Paths
DEFAULT_COOKIES_FILENAME = "cookies.json"
DEFAULT_BOOKS_DIR_NAME = "Books"
DEFAULT_LOG_FILE_PREFIX = "info_"

# Settings
USE_PROXY = False  # Default proxy usage
PROXIES = {"https": "https://127.0.0.1:8080"}  # Default proxy settings

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/90.0.4430.212 Safari/537.36"
)

DEFAULT_REQUEST_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": DEFAULT_USER_AGENT,
    # Referer is often request-specific, so it might be better to add it per request or per client type
    # For example, LOGIN_ENTRY_URL is a common referer for many initial requests.
    "Referer": LOGIN_ENTRY_URL 
}

# Specific headers for registration related requests
# These can be merged with DEFAULT_REQUEST_HEADERS by the client using them.
REGISTER_REQUEST_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Referer": REGISTER_URL  # Overrides the default Referer for registration calls
}

# Logging Configuration
LOG_LEVEL = "INFO"  # Can also use logging.INFO
LOG_FORMAT = "[%(asctime)s] %(levelname)s: %(message)s"
LOG_DATE_FORMAT = "%d/%b/%Y %H:%M:%S"
