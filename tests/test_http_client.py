import unittest
from unittest.mock import patch, MagicMock
import requests # Required for requests.exceptions.ConnectionError

from safaribooks_zero.http_client import HttpClient
from safaribooks_zero.exceptions import NetworkConnectionError, HttpRequestError
import safaribooks_zero.config as config

class TestHttpClient(unittest.TestCase):

    def setUp(self):
        # Instantiate HttpClient without specific base_headers or proxies for default tests
        # These can be overridden in specific test methods if needed
        self.client = HttpClient()

    @patch('safaribooks_zero.http_client.requests.Session.request')
    def test_successful_get_request(self, mock_request):
        # Configure the mock_request to return a MagicMock object representing a successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'Success'
        mock_response.json.return_value = {'key': 'value'}
        # Mock the raw headers for cookie handling
        mock_response.raw = MagicMock()
        mock_response.raw.headers = MagicMock()
        mock_response.raw.headers.getlist.return_value = [] # No cookies for this test
        
        mock_request.return_value = mock_response

        response = self.client.get('http://example.com', params={'test': '123'})

        # Assert that mock_request was called correctly
        mock_request.assert_called_once_with(
            'GET', 
            'http://example.com', 
            data=None, 
            json=None, # get uses json_data=None
            params={'test': '123'} # Check for params
        )
        # Assert that the returned response object is the one from mock_request
        self.assertEqual(response, mock_response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, 'Success')
        self.assertEqual(response.json(), {'key': 'value'})

    @patch('safaribooks_zero.http_client.requests.Session.request')
    def test_http_request_error_raised(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = 'Not Found'
        mock_response.raw = MagicMock() # Mock raw attribute
        mock_response.raw.headers = MagicMock()
        mock_response.raw.headers.getlist.return_value = []
        mock_request.return_value = mock_response

        with self.assertRaises(HttpRequestError) as cm:
            self.client.get('http://example.com/notfound')
        
        self.assertEqual(cm.exception.status_code, 404)
        self.assertIn("Unexpected status code 404", str(cm.exception))

    @patch('safaribooks_zero.http_client.requests.Session.request')
    def test_network_connection_error_raised(self, mock_request):
        mock_request.side_effect = requests.exceptions.ConnectionError("Test connection error")

        with self.assertRaises(NetworkConnectionError) as cm:
            self.client.get('http://example.com')
        self.assertIn("Network connection error for GET http://example.com: Test connection error", str(cm.exception))

    @patch('safaribooks_zero.http_client.COOKIE_FLOAT_MAX_AGE_PATTERN')
    def test_handle_cookie_update(self, mock_pattern_search):
        # Mock the regex search to identify the float max-age cookie
        # The first cookie is standard, the second has float max-age
        mock_pattern_search.side_effect = lambda x: True if "float_max_age" in x else False
        
        mock_headers = MagicMock()
        sample_cookies = [
            "standard_cookie=value1; path=/",
            "float_max_age_cookie=value2; max-age=3600.0; path=/" 
        ]
        mock_headers.getlist.return_value = sample_cookies
        
        # Mock the session's cookie jar set method to check it's called
        self.client.session.cookies.set = MagicMock()

        self.client.handle_cookie_update(mock_headers)

        # Assert that session.cookies.set was called for the float max-age cookie
        self.client.session.cookies.set.assert_called_once_with(
            "float_max_age_cookie", "value2"
        )
        # Assert getlist was called
        mock_headers.getlist.assert_called_once_with('Set-Cookie')


    @patch('safaribooks_zero.http_client.requests.Session.request')
    def test_custom_headers_and_proxies(self, mock_request):
        custom_headers = {"X-Custom-Header": "TestValue"}
        custom_proxies = {"https": "http://myproxy.example.com:8080"}
        
        # Create a new client instance with custom headers and proxies
        # This also tests if HttpClient correctly uses config defaults if some args are None
        client_with_custom = HttpClient(
            base_headers=custom_headers, 
            proxies=custom_proxies,
            user_agent="TestUserAgent/1.0" # Also test user_agent setting
        )

        # Configure mock_request for a basic successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raw = MagicMock()
        mock_response.raw.headers = MagicMock()
        mock_response.raw.headers.getlist.return_value = []
        mock_request.return_value = mock_response

        client_with_custom.get('http://example.com')

        # Check that the session object within the client has the custom headers and proxies
        # Headers are merged with defaults, so check for inclusion
        self.assertIn("X-Custom-Header", client_with_custom.session.headers)
        self.assertEqual(client_with_custom.session.headers["X-Custom-Header"], "TestValue")
        self.assertEqual(client_with_custom.session.headers["User-Agent"], "TestUserAgent/1.0")
        
        self.assertIn("https", client_with_custom.session.proxies)
        self.assertEqual(client_with_custom.session.proxies["https"], "http://myproxy.example.com:8080")
        
        # Verify the request was made (even if we don't check args deeply here, already done in other tests)
        mock_request.assert_called_once()

if __name__ == '__main__':
    unittest.main()
