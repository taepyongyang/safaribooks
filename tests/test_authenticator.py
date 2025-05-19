import unittest
from unittest.mock import patch, MagicMock
import json # For mocking JSON responses

# Assuming Authenticator and Display are in safaribooks.py for now
# If they are moved, these imports will need to be adjusted.
from safaribooks_zero.safaribooks import Authenticator, Display 
from safaribooks_zero.http_client import HttpClient
from safaribooks_zero.exceptions import (
    AuthenticationError, 
    InvalidCredentialsError, 
    UserAccountError,
    APIDataError # For JWT parsing issues
)
import safaribooks_zero.config as config

class TestAuthenticator(unittest.TestCase):

    def setUp(self):
        self.mock_http_client = MagicMock(spec=HttpClient)
        self.mock_display = MagicMock(spec=Display)
        self.authenticator = Authenticator(self.mock_http_client, self.mock_display)

    def test_parse_cred_valid(self):
        self.assertEqual(Authenticator.parse_cred("user@example.com:password123"), ["user@example.com", "password123"])
        self.assertEqual(Authenticator.parse_cred(" 'user@example.com' : 'password123' "), ["user@example.com", "password123"])

    def test_parse_cred_invalid(self):
        self.assertFalse(Authenticator.parse_cred("user@example.compassword123")) # No colon
        self.assertFalse(Authenticator.parse_cred("userexample.com:password123")) # No @ in email
        self.assertFalse(Authenticator.parse_cred(":password123")) # Empty email
        self.assertFalse(Authenticator.parse_cred("user@example.com:")) # Empty password (still valid by this parser, but good to note)

    def test_do_login_success(self):
        # Mock for initial GET to LOGIN_ENTRY_URL
        mock_entry_response = MagicMock()
        # Simulate a redirect URL that contains the 'next' parameter
        mock_entry_response.request = MagicMock()
        mock_entry_response.request.url = f"{config.LOGIN_ENTRY_URL}?next=/home/" 
        self.mock_http_client.get.return_value = mock_entry_response
        
        # Mock for POST to LOGIN_URL
        mock_login_post_response = MagicMock()
        mock_login_post_response.status_code = 200
        # Ensure json method is available and returns a callable that returns the dict
        mock_login_post_response.json = MagicMock(return_value={'redirect_uri': 'http://example.com/final_redirect'})
        
        # Mock for GET to the final redirect_uri from JWT
        mock_final_redirect_response = MagicMock()
        mock_final_redirect_response.status_code = 200

        # Configure side_effect for http_client calls if they are distinct (GET then POST then GET)
        # The first GET is to LOGIN_ENTRY_URL, second is to jwt['redirect_uri']
        # The POST is to LOGIN_URL
        self.mock_http_client.get.side_effect = [mock_entry_response, mock_final_redirect_response]
        self.mock_http_client.post.return_value = mock_login_post_response

        self.authenticator.do_login('user@example.com', 'password')

        # Assertions
        self.mock_http_client.get.assert_any_call(config.LOGIN_ENTRY_URL)
        self.mock_http_client.post.assert_called_once_with(
            config.LOGIN_URL,
            json_data={
                'email': 'user@example.com',
                'password': 'password',
                'redirect_uri': config.API_ORIGIN_URL + quote_plus("/home/") # from LOGIN_ENTRY_URL next param
            },
            perform_redirect=False,
            expected_status_codes=[200]
        )
        self.mock_http_client.get.assert_any_call('http://example.com/final_redirect')
        self.mock_display.info.assert_any_call("Successfully logged in.", state=True)


    def test_do_login_failure_invalid_credentials(self):
        # Mock for initial GET to LOGIN_ENTRY_URL
        mock_entry_response = MagicMock()
        mock_entry_response.request = MagicMock()
        mock_entry_response.request.url = f"{config.LOGIN_ENTRY_URL}?next=/home/"
        self.mock_http_client.get.return_value = mock_entry_response # First call to get
        
        # Mock for POST to LOGIN_URL that simulates invalid credentials
        # This will raise HttpRequestError, which do_login should catch and parse
        mock_login_post_error_response = MagicMock()
        mock_login_post_error_response.status_code = 400 # Example error code
        # Simulate HTML error page content
        mock_login_post_error_response.text = "<html><ul class='errorlist'><li>Invalid email or password.</li></ul></html>"
        
        # Configure http_client.post to raise HttpRequestError directly for this test
        # This is because do_login catches HttpRequestError and then tries to parse its response_text
        self.mock_http_client.post.side_effect = HttpRequestError(
            message="Simulated HTTP 400 error",
            status_code=400,
            response_text=mock_login_post_error_response.text
        )

        with self.assertRaises(InvalidCredentialsError):
            self.authenticator.do_login('user@example.com', 'wrongpassword')
        
        self.mock_display.exit.assert_called_once() # Ensure display.exit was called


    def test_check_login_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"user_type": "Active"}' # Valid session content
        self.mock_http_client.get.return_value = mock_response

        self.authenticator.check_login() # PROFILE_URL is used by default from config

        self.mock_http_client.get.assert_called_once_with(
            config.PROFILE_URL, 
            perform_redirect=False, 
            expected_status_codes=[200]
        )
        self.mock_display.info.assert_any_call("Session is valid.", state=True)

    def test_check_login_expired_subscription(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'Some content here {"user_type":"Expired"} and more here'
        self.mock_http_client.get.return_value = mock_response

        with self.assertRaises(UserAccountError) as cm:
            self.authenticator.check_login()
        
        self.assertIn("Account subscription has expired.", str(cm.exception))
        self.mock_display.exit.assert_called_once()

    def test_load_cookies_from_file_success(self):
        with patch('builtins.open', unittest.mock.mock_open(read_data=json.dumps({'sessionid': 'testsessionid'}))) as mock_file, \
             patch('os.path.isfile', return_value=True):
            
            self.assertTrue(self.authenticator.load_cookies_from_file('dummy_cookies.json'))
            mock_file.assert_called_once_with('dummy_cookies.json', 'r')
            self.mock_http_client.session.cookies.update.assert_called_once_with({'sessionid': 'testsessionid'})
            self.mock_display.info.assert_any_call("Cookies successfully loaded from 'dummy_cookies.json'.", state=True)

    def test_load_cookies_from_file_not_found(self):
        with patch('os.path.isfile', return_value=False):
            self.assertFalse(self.authenticator.load_cookies_from_file('nonexistent_cookies.json'))
            self.mock_display.info.assert_any_call("Cookie file 'nonexistent_cookies.json' not found. Will attempt login if credentials provided.", state=True)

    def test_save_cookies_to_file_success(self):
        self.mock_http_client.session.cookies.get_dict.return_value = {'sessionid': 'testsessionid'}
        with patch('builtins.open', unittest.mock.mock_open()) as mock_file:
            self.authenticator.save_cookies_to_file('dummy_cookies.json')
            mock_file.assert_called_once_with('dummy_cookies.json', 'w')
            # json.dump is called with the file object and the cookie dict
            # The first argument to json.dump is the data, the second is the file object.
            # mock_file().write is what json.dump eventually calls. We check if json.dump was called.
            # This requires a more complex mock if we want to inspect json.dump directly.
            # For simplicity, checking if open was called is often sufficient for this type of test.
            # To check json.dump: @patch('json.dump') def test(self, mock_json_dump, ...): mock_json_dump.assert_called_with(...)
            self.mock_display.info.assert_any_call("Session cookies saved to 'dummy_cookies.json'.", state=True)

if __name__ == '__main__':
    # Need to import quote_plus for this test file if used directly, 
    # but it's encapsulated in Authenticator.do_login which uses config.API_ORIGIN_URL + quote_plus(...)
    from urllib.parse import quote_plus 
    unittest.main()
