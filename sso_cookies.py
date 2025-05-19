"""
Script for SSO support, saves and converts the cookie string retrieved by the browser.
Please follow:
- https://github.com/lorenzodifuccia/safaribooks/issues/26
- https://github.com/lorenzodifuccia/safaribooks/issues/150#issuecomment-555423085
- https://github.com/lorenzodifuccia/safaribooks/issues/2#issuecomment-367726544


Thanks: @elrob, @noxymon
"""

import json
import os
import argparse # Import argparse
from safaribooks_zero.exceptions import FileOperationError, SafariBooksError
from safaribooks_zero.config import DEFAULT_COOKIES_FILENAME # Import specific config


def transform(cookies_string, output_file_path): # Updated signature
    cookies = {}
    try:
        for cookie in cookies_string.split("; "):
            if "=" not in cookie:
                raise ValueError(f"Invalid cookie string part: '{cookie}'. Expected 'key=value'.")
            key, value = cookie.split("=", 1)
            cookies[key] = value
    except ValueError as e:
        raise SafariBooksError(f"Error parsing cookie string: {e}")


    print("Parsed cookies:", cookies) # For user feedback
    try:
        # Use the provided output_file_path parameter
        with open(output_file_path, 'w') as f:
            json.dump(cookies, f)
    except OSError as e:
        raise FileOperationError(f"Error saving cookie file to {output_file_path}: {e}") from e
    
    # Update success message to use the actual output file path
    print(f"\n\nDone! Cookie Jar saved into `{output_file_path}`. "
          "Now you can run `safaribooks.py` without the `--cred` argument (if using the default location or appropriate CLI arg).")


# Updated USAGE message, argparse will generate most of the help.
USAGE_INFO = """
This script transforms a browser cookie string into a JSON file compatible with safaribooks.py.

To get your cookie string:
1. Log in to Safari Books Online (learning.oreilly.com) in your web browser.
2. Open your browser's developer tools (usually F12).
3. Go to the "Console" tab.
4. Type `document.cookie` and press Enter.
5. Copy the entire string output.
"""

if __name__ == "__main__":
    import sys
    
    # Define PATH here as it's used for the default output file path
    PATH = os.path.dirname(os.path.realpath(__file__))
    default_output_location = os.path.join(PATH, DEFAULT_COOKIES_FILENAME)

    parser = argparse.ArgumentParser(
        description="Transform browser cookie string to JSON for safaribooks.py.",
        epilog=USAGE_INFO,
        formatter_class=argparse.RawTextHelpFormatter # Preserve formatting of epilog
    )
    parser.add_argument(
        "cookies_string",
        help="The cookie string copied from your browser's developer console."
    )
    parser.add_argument(
        "-o", "--output-file",
        dest="output_file",
        default=default_output_location,
        help=f"Optional path to save the cookies JSON file. Defaults to: {default_output_location}"
    )
    
    # Argparse handles "too few/many arguments" automatically.
    # If parsing fails, it will print help and exit.
    args = parser.parse_args()

    try:
        transform(args.cookies_string, args.output_file)
    except SafariBooksError as e:
        print(f"Error: {e}", file=sys.stderr) # Print errors to stderr
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
