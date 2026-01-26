"""
SafariBooks Downloader & EPUB Generator

This script allows users to download and generate EPUB files from Safari Books Online (O'Reilly) using their credentials or session cookies.

Key Components:
- Display: Handles all user-facing output, logging, and error reporting.
- WinQueue: Multiprocessing queue workaround for Windows compatibility.
- SafariBooks: Main logic for authentication, downloading, parsing, and EPUB creation.

Usage:
    python safaribooks_refactored.py <BOOK ID> [options]

See README.md for details.
"""

import argparse
import sys

# Import configuration constants
from safaribooks_config import SAFARI_BASE_URL
from safaribooks_process import SafariBooks

# MAIN
if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog="safaribooks.py",
        description="Download and generate an EPUB of your favorite books from Safari Books Online.",
        add_help=False,
        allow_abbrev=False
    )

    login_arg_group = parser.add_mutually_exclusive_group()
    login_arg_group.add_argument(
        "--cred", metavar="<EMAIL:PASS>", default=False,
        help="Credentials used to perform the auth login on Safari Books Online. Es. ` --cred \"account_mail@mail.com:password01\" `."
    )
    login_arg_group.add_argument(
        "--login", action='store_true',
        help="Prompt for credentials used to perform the auth login on Safari Books Online."
    )

    parser.add_argument(
        "--no-cookies", dest="no_cookies", action='store_true',
        help="Prevent your session data to be saved into `cookies.json` file."
    )
    parser.add_argument(
        "--kindle", dest="kindle", action='store_true',
        help="Add some CSS rules that block overflow on `table` and `pre` elements. Use this option if you're going to export the EPUB to E-Readers like Amazon Kindle."
    )
    parser.add_argument(
        "--preserve-log", dest="log", action='store_true',
        help="Leave the `info_XXXXXXXXXXXXX.log` file even if there isn't any error."
    )
    parser.add_argument(
        "--debug", dest="debug", action='store_true',
        help="Enable diagnostic mode: track download completeness, validate EPUB integrity, and generate diagnostic report."
    )
    parser.add_argument(
        "--convert", dest="convert", action='store_true',
        help="After download, run EPUB through Calibre conversion (epub→mobi→epub) to clean formatting. Requires Calibre installed."
    )
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help='Show this help message.')
    parser.add_argument(
        "bookid", metavar='<BOOK ID>',
        help=f"Book digits ID that you want to download. You can find it in the URL (X-es): `{SAFARI_BASE_URL}/library/view/book-name/XXXXXXXXXXXXX/`"
    )

    args = parser.parse_args()

    # Handle deprecated --cred/--login flags
    if args.cred or args.login:
        print("\n" + "=" * 60)
        print("DEPRECATION NOTICE")
        print("=" * 60)
        print("The --cred and --login options are deprecated.")
        print("O'Reilly has changed their authentication API.")
        print()
        print("The app will now use browser-based authentication:")
        print("  1. A Chrome window will open to O'Reilly's login page")
        print("  2. You log in normally (supports SSO, 2FA, etc.)")
        print("  3. Press ENTER when done - cookies are captured automatically")
        print("=" * 60 + "\n")
        # Clear the cred to force browser auth path
        args.cred = None

    # Validate --no-cookies usage
    if args.no_cookies and not args.cred:
        # --no-cookies is now mostly irrelevant but keep for backwards compat
        pass

    SafariBooks(args)
    sys.exit(0)
