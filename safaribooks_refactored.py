#!/usr/bin/env python3
# coding: utf-8
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

import re
import os
import sys
import json
import shutil
import pathlib
import getpass
import logging
import argparse
import requests
import traceback
from html import escape
from random import random
from lxml import html, etree
from multiprocessing import Process, Queue, Value
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus

# Import configuration constants
from safaribooks_config import (
    PATH, COOKIES_FILE, ORLY_BASE_HOST, SAFARI_BASE_HOST, API_ORIGIN_HOST,
    ORLY_BASE_URL, SAFARI_BASE_URL, API_ORIGIN_URL, PROFILE_URL, USE_PROXY, PROXIES
)

# Import WinQueue workaround for Windows
from safaribooks_winqueue import WinQueue

# Import Display from new module
from safaribooks_display import Display

from safaribooks_process import SafariBooks

# ...existing code...
if __name__ == "__main__":
    arguments = argparse.ArgumentParser(prog="safaribooks.py",
                                        description="Download and generate an EPUB of your favorite books"
                                                    " from Safari Books Online.",
                                        add_help=False,
                                        allow_abbrev=False)

    login_arg_group = arguments.add_mutually_exclusive_group()
    login_arg_group.add_argument(
        "--cred", metavar="<EMAIL:PASS>", default=False,
        help="Credentials used to perform the auth login on Safari Books Online."
             " Es. ` --cred \"account_mail@mail.com:password01\" `."
    )
    login_arg_group.add_argument(
        "--login", action='store_true',
        help="Prompt for credentials used to perform the auth login on Safari Books Online."
    )

    arguments.add_argument(
        "--no-cookies", dest="no_cookies", action='store_true',
        help="Prevent your session data to be saved into `cookies.json` file."
    )
    arguments.add_argument(
        "--kindle", dest="kindle", action='store_true',
        help="Add some CSS rules that block overflow on `table` and `pre` elements."
             " Use this option if you're going to export the EPUB to E-Readers like Amazon Kindle."
    )
    arguments.add_argument(
        "--preserve-log", dest="log", action='store_true', help="Leave the `info_XXXXXXXXXXXXX.log`"
                                                                " file even if there isn't any error."
    )
    arguments.add_argument("--help", action="help", default=argparse.SUPPRESS, help='Show this help message.')
    arguments.add_argument(
        "bookid", metavar='<BOOK ID>',
        help="Book digits ID that you want to download. You can find it in the URL (X-es):"
             " `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`"
    )

    args_parsed = arguments.parse_args()
    if args_parsed.cred or args_parsed.login:
        user_email = ""
        pre_cred = ""

        if args_parsed.cred:
            pre_cred = args_parsed.cred

        else:
            user_email = input("Email: ")
            passwd = getpass.getpass("Password: ")
            pre_cred = user_email + ":" + passwd

        parsed_cred = SafariBooks.parse_cred(pre_cred)

        if not parsed_cred:
            arguments.error("invalid credential: %s" % (
                args_parsed.cred if args_parsed.cred else (user_email + ":*******")
            ))

        args_parsed.cred = parsed_cred

    else:
        if args_parsed.no_cookies:
            arguments.error("invalid option: `--no-cookies` is valid only if you use the `--cred` option")

    SafariBooks(args_parsed)
    # Hint: do you want to download more then one book once, initialized more than one instance of `SafariBooks`...
    sys.exit(0)
