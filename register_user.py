import re
# safaribooks import is no longer needed for base URLs or headers.
from safaribooks_zero.exceptions import (
    SafariBooksError,
    NetworkConnectionError,
    HttpRequestError,
    UserAccountError,
    CSRFTokenError
)
from safaribooks_zero.http_client import HttpClient
import safaribooks_zero.config as config # Import the config module

# URLs are now sourced from config
# No need for DEBUG USE_PROXY and PROXIES here, HttpClient will use config values.

CSRF_TOKEN_RE = re.compile(r"(?<=name='csrfmiddlewaretoken' value=')([^']+)")


class Register:
    def __init__(self, email, password, first_name, second_name, country="US", referrer="podcast"):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.second_name = second_name
        self.country = country
        self.referrer = referrer

        self.csrf = None

        # Merge default headers with registration-specific headers
        # HttpClient will be initialized with these merged headers.
        # Proxies and SSL verification will be handled by HttpClient using config defaults
        # if not overridden here (though we will use config defaults by not passing them).
        merged_headers = config.DEFAULT_REQUEST_HEADERS.copy()
        merged_headers.update(config.REGISTER_REQUEST_HEADERS)
        
        self.http_client = HttpClient(
            base_headers=merged_headers,
            # Proxies and verify_ssl will use defaults from HttpClient,
            # which should ideally also use the config.py for its defaults.
            # For now, assuming HttpClient's defaults are sufficient or it picks from config.
            # If HttpClient needs explicit proxy config:
            proxies=config.PROXIES if config.USE_PROXY else None,
            verify_ssl=not config.USE_PROXY
        )

        # self.register() # Removed automatic call

    def register(self):
        # Take first cookie + csrf
        try:
            response = self.http_client.get(config.REGISTER_URL) # Use config URL
        except NetworkConnectionError as e:
            raise NetworkConnectionError("Unable to reach registration page during initial CSRF fetch.") from e
        except HttpRequestError as e:
            raise HttpRequestError(f"HTTP error during initial CSRF fetch: {e.status_code}", status_code=e.status_code, response_text=e.response_text) from e

        if "csrfmiddlewaretoken' value='" not in response.text: # type: ignore
            raise CSRFTokenError("CSRF token not present in registration page response.")

        csrf_search = CSRF_TOKEN_RE.findall(response.text) # type: ignore
        if not len(csrf_search):
            raise CSRFTokenError("CSRF token could not be extracted using regex.")

        self.csrf = csrf_search[0]

        # Check user validity
        try:
            response = self.http_client.get(config.CHECK_EMAIL_URL, params={"email": self.email}) # Use config URL
        except NetworkConnectionError as e:
            raise NetworkConnectionError("Unable to check email availability due to network error.") from e
        except HttpRequestError as e:
            raise HttpRequestError(f"HTTP error while checking email: {e.status_code}", status_code=e.status_code, response_text=e.response_text) from e

        response_dict = response.json() # type: ignore
        if not response_dict["success"]:
            raise UserAccountError(f"Email check failed: {response_dict.get('message', 'No message provided')}")

        # Check password validity
        try:
            response = self.http_client.post(config.CHECK_PWD_URL, data={ # Use config URL
                "csrfmiddlewaretoken": self.csrf,
                "password1": self.password,
                "field_name": "password1"
            })
        except NetworkConnectionError as e:
            raise NetworkConnectionError("Unable to check password validity due to network error.") from e
        except HttpRequestError as e:
            raise HttpRequestError(f"HTTP error while checking password: {e.status_code}", status_code=e.status_code, response_text=e.response_text) from e

        response_dict = response.json() # type: ignore
        if not response_dict["valid"]:
            raise UserAccountError(f"Password check failed: {response_dict.get('msg', 'No message provided')}")

        # Register
        try:
            response = self.http_client.post(config.REGISTER_URL, data={ # Use config URL
                "next": "",
                "trial_length": 10,
                "csrfmiddlewaretoken": self.csrf,
                "first_name": self.first_name,
                "last_name": self.second_name,
                "email": self.email,
                "password1": self.password,
                "country": self.country,
                "referrer": "podcast",
                "recently_viewed_bits": "[]"
            }, expected_status_codes=[201]) # check_status_code is True by default
        except NetworkConnectionError as e:
            raise NetworkConnectionError("Unable to submit registration due to network error.") from e
        except HttpRequestError as e: # This will be raised by HttpClient if status is not 201
            raise HttpRequestError(
                f"Registration failed. Expected status 201 but got {e.status_code}.",
                status_code=e.status_code,
                response_text=e.response_text
            ) from e
        
        success_message = f"[*] Account registered: \nEMAIL: {self.email}\nPASSWORD: {self.password}"
        return success_message


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("[!] Error: too few arguments.\nRun `register_user.py EMAIL PASSWORD`.")
        sys.exit(1)

    elif len(sys.argv) > 3:
        print("[!] Error: too much arguments, try to enclose the string with quote '\"'.")
        sys.exit(1)

    FIRST_NAME = "Safari"
    SECOND_NAME = "Download"

    try:
        registrar = Register(sys.argv[1], sys.argv[2], FIRST_NAME, SECOND_NAME)
        registration_result = registrar.register()
        print(registration_result) # Print the success message from register()
    except SafariBooksError as e:
        print(f"Registration failed: {e}")
        if hasattr(e, 'response_text') and e.response_text:
            print(f"Server response: {e.response_text}")
        sys.exit(1)
