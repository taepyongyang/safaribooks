import requests
from safaribooks_zero.exceptions import NetworkConnectionError, HttpRequestError
import safaribooks_zero.config as config # Import config
import re

COOKIE_FLOAT_MAX_AGE_PATTERN = re.compile(r'(max-age=\d*\.\d*)', re.IGNORECASE)

class HttpClient:
    def __init__(self, base_headers=None, user_agent=None, proxies=None, verify_ssl=True):
        self.session = requests.Session()

        # Initialize headers
        actual_headers = config.DEFAULT_REQUEST_HEADERS.copy() if base_headers is None else base_headers.copy()
        
        # Set User-Agent
        if user_agent:
            actual_headers["User-Agent"] = user_agent
        elif "User-Agent" not in actual_headers : # If not in base_headers and no specific one given
             actual_headers["User-Agent"] = config.DEFAULT_USER_AGENT

        self.session.headers.update(actual_headers)

        # Proxies: Use provided, else from config, else None
        if proxies is not None:
            self.session.proxies = proxies
        elif config.USE_PROXY:
            self.session.proxies = config.PROXIES
        
        self.session.verify = verify_ssl

        # This is a simple way to keep track; could be more sophisticated.
        self.last_request_details = None

    def handle_cookie_update(self, response_headers):
        """
        Processes 'Set-Cookie' headers from a response and updates the session's cookies.
        Handles cases like float 'max-age' values in cookies.
        """
        set_cookie_headers = response_headers.getlist("Set-Cookie")
        for morsel in set_cookie_headers:
            if COOKIE_FLOAT_MAX_AGE_PATTERN.search(morsel):
                cookie_key, cookie_value = morsel.split(";")[0].split("=")
                self.session.cookies.set(cookie_key, cookie_value)
            # else:
                # The default requests cookie handling should manage standard cookies.
                # requests library automatically handles Set-Cookie headers if not manually processed like above.
                # However, explicit handling like above is from the original code, so keeping its spirit.
                # For simple Set-Cookie, session.cookies.update() would work after extracting from response.cookies
                # but the above handles a specific case.
                # If we let requests handle all, this method might only be for specific overrides.
                # For now, this matches the original intent for float max-age.
                # Requests itself will handle standard cookies set by the server.
                # This manual intervention is only for the float max-age case.
                pass


    def request(self, method, url, data=None, json_data=None, perform_redirect=True,
                check_status_code=True, expected_status_codes=None, **kwargs):
        """
        Generic request method.
        `expected_status_codes`: A list of integers. If provided, `check_status_code` will
                                 validate against this list. Otherwise, it checks for 2xx.
        """
        original_allow_redirects = kwargs.pop('allow_redirects', True)
        if not perform_redirect:
            kwargs['allow_redirects'] = False
        
        # Store details for logging/debugging, similar to original display.last_request
        self.last_request_details = {
            "url": url, "method": method, "data": data, "json_data": json_data,
            "kwargs": kwargs, "response_status": None, "response_headers": None, "response_text": None
        }

        try:
            response = self.session.request(method, url, data=data, json=json_data, **kwargs)
            # Update last request details with response info
            self.last_request_details["response_status"] = response.status_code
            self.last_request_details["response_headers"] = response.headers
            # Be careful with response.text for large responses or streamed responses
            if not kwargs.get("stream"):
                 try:
                    self.last_request_details["response_text"] = response.text
                 except Exception: # Handle cases where .text might not be appropriate (e.g. early error)
                    self.last_request_details["response_text"] = "N/A (streamed or error accessing text)"


            # Manual cookie handling for specific cases like float max-age
            # requests session will handle standard cookies automatically.
            self.handle_cookie_update(response.raw.headers)


            # Simplified redirect handling: requests handles redirects by default if allow_redirects=True.
            # The original `requests_provider` had manual recursive calls for redirects.
            # Here, we rely on `requests`' default behavior for `allow_redirects=True`.
            # If `perform_redirect` is False, `allow_redirects` was set to False.
            # If `perform_redirect` is True, `allow_redirects` is True (its default in requests).

        except requests.RequestException as e:
            self.last_request_details["response_text"] = f"RequestException: {e}"
            raise NetworkConnectionError(f"Network connection error for {method} {url}: {e}") from e

        if check_status_code:
            is_success = False
            if expected_status_codes:
                if response.status_code in expected_status_codes:
                    is_success = True
            elif 200 <= response.status_code < 300: # Default: 2xx is success
                is_success = True

            if not is_success:
                raise HttpRequestError(
                    f"Unexpected status code {response.status_code} for {method} {url}.",
                    status_code=response.status_code,
                    response_text=response.text
                )
        
        return response

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, data=None, json_data=None, **kwargs):
        return self.request("POST", url, data=data, json_data=json_data, **kwargs)

    def get_last_request_details(self):
        """Returns the details of the last request made, for logging purposes."""
        return self.last_request_details
