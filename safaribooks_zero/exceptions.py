class SafariBooksError(Exception):
    """Base class for all custom errors in this application."""
    pass

class NetworkConnectionError(SafariBooksError):
    """For issues like requests.ConnectionError, requests.ConnectTimeout."""
    pass

class HttpRequestError(SafariBooksError):
    """For non-2xx HTTP status codes where an error message might be in the response."""
    def __init__(self, message, status_code=None, response_text=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text

class AuthenticationError(SafariBooksError):
    """For login failures or session expiry."""
    pass

class UserAccountError(SafariBooksError):
    """For specific issues related to user account status (e.g. expired subscription, email not available)."""
    pass

class CSRFTokenError(SafariBooksError):
    """For issues related to fetching or using CSRF tokens."""
    pass

class APIDataError(SafariBooksError):
    """When API responses are not in the expected format or data is missing."""
    pass

class ParsingError(SafariBooksError):
    """For errors during HTML or XML parsing."""
    pass

class FileOperationError(SafariBooksError):
    """For errors related to file I/O (e.g., cannot create directory, cannot write file)."""
    pass

class BookNotFoundError(APIDataError):
    """Specifically when a book ID is not found."""
    pass

class InvalidCredentialsError(AuthenticationError):
    """For incorrect username/password."""
    pass
