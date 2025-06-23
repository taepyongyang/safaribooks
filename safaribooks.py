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
import getpass
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
    parser.add_argument("--help", action="help", default=argparse.SUPPRESS, help='Show this help message.')
    parser.add_argument(
        "bookid", metavar='<BOOK ID>',
        help=f"Book digits ID that you want to download. You can find it in the URL (X-es): `{SAFARI_BASE_URL}/library/view/book-name/XXXXXXXXXXXXX/`"
    )

    args = parser.parse_args()
    if args.cred or args.login:
        if args.cred:
            pre_cred = args.cred
            user_email = ""
        else:
            user_email = input("Email: ")
            passwd = getpass.getpass("Password: ")
            pre_cred = f"{user_email}:{passwd}"

        parsed_cred = SafariBooks.parse_cred(pre_cred)
        if not parsed_cred:
            parser.error(f"invalid credential: {args.cred if args.cred else user_email + ':*******'}")
            sys.exit(1)
        args.cred = parsed_cred
    else:
        if args.no_cookies:
            parser.error("invalid option: `--no-cookies` is valid only if you use the `--cred` option")
            sys.exit(1)

    SafariBooks(args)
    sys.exit(0)
