#!/usr/bin/env python3
# coding: utf-8
import re
import os
import sys
import safaribooks_zero.config as config
import json
import shutil
import pathlib
import getpass
import logging
import argparse
import traceback # requests is no longer directly used in this file
from html import escape
# import requests # No longer directly used
from safaribooks_zero.exceptions import (
    SafariBooksError,
    NetworkConnectionError, # Still needed for try-except blocks
    HttpRequestError,     # Still needed for try-except blocks
    AuthenticationError,
    UserAccountError,
    APIDataError,
    ParsingError,
    BookNotFoundError,
    InvalidCredentialsError,
    FileOperationError
)
from safaribooks_zero.http_client import HttpClient # Import the new HttpClient

from random import random
from lxml import html, etree
from multiprocessing import Process, Queue, Value
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus

# PATH definition remains the same as it's relative to the current file
PATH = os.path.dirname(os.path.realpath(__file__))
# COOKIES_FILE now uses config
COOKIES_FILE = os.path.join(PATH, config.DEFAULT_COOKIES_FILENAME)

# URLs like ORLY_BASE_HOST, SAFARI_BASE_URL, etc., are now imported from config or constructed using config values.
# No need to define them here.
# DEBUG USE_PROXY and PROXIES are also removed, will use from config.


class Display:
    # BASE_FORMAT removed, will use config.LOG_FORMAT and config.LOG_DATE_FORMAT

    SH_DEFAULT = "\033[0m" if "win" not in sys.platform else ""
    SH_YELLOW = "\033[33m" if "win" not in sys.platform else ""
    SH_BG_RED = "\033[41m" if "win" not in sys.platform else ""
    SH_BG_YELLOW = "\033[43m" if "win" not in sys.platform else ""

    def __init__(self, logger, log_file_path): # Accepts a logger instance and log_file_path
        self.logger = logger # Store the passed logger
        self.log_file_path = log_file_path # Store for potential use (e.g., deletion logic)
        self.output_dir = ""
        self.output_dir_set = False
        
        self.columns, _ = shutil.get_terminal_size()

        self.logger.info("** Welcome to SafariBooks! **") # Use the passed logger

        self.book_ad_info = False
        self.css_ad_info = Value("i", 0)
        self.images_ad_info = Value("i", 0)
        # self.last_request = (None,) # This will be handled by HttpClient's details
        self.http_client_ref = None 
        self.in_error = False # This flag helps in final log file removal decision

        self.state_status = Value("i", 0)
        # sys.excepthook = self.unhandled_exception # This will be handled differently

    def set_output_dir(self, output_dir):
        # self.info calls self.log which now uses self.logger
        self.info(f"Output directory:\n    {output_dir}")
        self.output_dir = output_dir
        self.output_dir_set = True

    def unregister(self):
        # No self.logger.handlers[0].close() as logger is managed externally.
        # Restore default excepthook if it was changed.
        sys.excepthook = sys.__excepthook__

    def log(self, message, level=logging.INFO): # Added level parameter
        # All logging goes through the passed-in logger instance
        # The original try-except for encoding is removed; Python's logging handles encoding.
        self.logger.log(level, message)

    def out(self, put): # This method remains for direct console output
        pattern = "\r{!s}\r{!s}\n"
        try:
            s = pattern.format(" " * self.columns, str(put, "utf-8", "replace"))
        except TypeError:
            s = pattern.format(" " * self.columns, put)
        sys.stdout.write(s)

    def info(self, message, state=False):
        self.logger.info(message) # Log the message using the logger
        # Console output formatting remains
        output = (self.SH_YELLOW + "[*]" + self.SH_DEFAULT if not state else
                  self.SH_BG_YELLOW + "[-]" + self.SH_DEFAULT) + f" {message}"
        self.out(output)

    def error(self, error_message):
        if not self.in_error:
            self.in_error = True
        self.logger.error(error_message) # Log the error using the logger
        # Console output formatting remains
        output = self.SH_BG_RED + "[#]" + self.SH_DEFAULT + f" {error_message}"
        self.out(output)

    def exit(self, error_message, http_client_for_last_request=None):
        # self.error(error_message) should have been called before this to log and display the error.
        # This method now primarily focuses on the exit sequence UI and raising the exception.
        
        if self.output_dir_set:
            output = (self.SH_YELLOW + "[+]" + self.SH_DEFAULT +
                      f" Please delete the output directory '{self.output_dir}'"
                      " and restart the program.")
            self.out(output)

        output = self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Aborting..."
        self.out(output)

        client_to_use = http_client_for_last_request if http_client_for_last_request else self.http_client_ref
        if client_to_use:
            self.save_last_request(client_to_use.get_last_request_details())
        else:
            # Log this situation using the logger
            self.logger.warning("Could not save last request details: HttpClient reference not available during exit.")
        
        raise SafariBooksError(error_message)

    def unhandled_exception(self, exc_type, exc_value, tb_obj): # Renamed tb to tb_obj
        # Log critical error with full traceback information
        self.logger.critical(
            "Unhandled Exception: %s (type: %s)",
            exc_value,
            exc_type.__name__,
            exc_info=(exc_type, exc_value, tb_obj) # Pass exc_info for traceback
        )
        # The original called self.exit, which raised SafariBooksError.
        # If sys.excepthook is set to this, it should probably perform a clean exit or re-raise.
        # For now, it just logs. The main program's top-level try-except will handle exiting.
        # However, to maintain similar behavior of `exit` being called:
        self.exit(f"Unhandled Exception: {exc_value} (type: {exc_type.__name__})")


    def save_last_request(self, last_request_details):
        if last_request_details:
            log_msg = "Last request details:\n"
            log_msg += f"\tURL: {last_request_details.get('url')}\n"
            log_msg += f"\tMethod: {last_request_details.get('method')}\n"
            log_msg += f"\tData: {last_request_details.get('data')}\n"
            log_msg += f"\tJSON Data: {last_request_details.get('json_data')}\n"
            log_msg += f"\tKwargs: {last_request_details.get('kwargs')}\n"
            log_msg += f"\tResponse Status: {last_request_details.get('response_status')}\n"
            log_msg += "\tResponse Headers:\n"
            response_headers = last_request_details.get('response_headers')
            if response_headers:
                for k, v in response_headers.items(): # type: ignore
                    log_msg += f"\t\t{k}: {v}\n"
            else:
                log_msg += "\t\tN/A\n"
            log_msg += f"\tResponse Text Preview: { (last_request_details.get('response_text') or '')[:500] }...\n"
            self.logger.info(log_msg) # Use self.logger.info
        else:
            self.logger.info("No last request details available to save.") # Use self.logger.info


    def intro(self): # UI method, uses self.out
        output = self.SH_YELLOW + ("""
       ____     ___         _
      / __/__ _/ _/__ _____(_)
     _\ \/ _ `/ _/ _ `/ __/ /
    /___/\_,_/_/ \_,_/_/ /_/
      / _ )___  ___  / /__ ___
     / _  / _ \/ _ \/  '_/(_-<
    /____/\___/\___/_/\_\/___/
""" if random() > 0.5 else """
 ██████╗     ██████╗ ██╗  ██╗   ██╗██████╗
██╔═══██╗    ██╔══██╗██║  ╚██╗ ██╔╝╚════██╗
██║   ██║    ██████╔╝██║   ╚████╔╝   ▄███╔╝
██║   ██║    ██╔══██╗██║    ╚██╔╝    ▀▀══╝
╚██████╔╝    ██║  ██║███████╗██║     ██╗
 ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
""") + self.SH_DEFAULT
        output += "\n" + "~" * (self.columns // 2)

        self.out(output)

    def parse_description(self, desc):
        if not desc:
            return "n/d"

        try:
            return html.fromstring(desc).text_content()

        except (html.etree.ParseError, html.etree.ParserError) as e:
            self.log("Error parsing the description: %s" % e)
            return "n/d"

    def book_info(self, info):
        description = self.parse_description(info.get("description", None)).replace("\n", " ")
        for t in [
            ("Title", info.get("title", "")), ("Authors", ", ".join(aut.get("name", "") for aut in info.get("authors", []))),
            ("Identifier", info.get("identifier", "")), ("ISBN", info.get("isbn", "")),
            ("Publishers", ", ".join(pub.get("name", "") for pub in info.get("publishers", []))),
            ("Rights", info.get("rights", "")),
            ("Description", description[:500] + "..." if len(description) >= 500 else description),
            ("Release Date", info.get("issued", "")),
            ("URL", info.get("web_url", ""))
        ]:
            self.info("{0}{1}{2}: {3}".format(self.SH_YELLOW, t[0], self.SH_DEFAULT, t[1]), True)

    def state(self, origin, done):
        progress = int(done * 100 / origin)
        bar = int(progress * (self.columns - 11) / 100)
        if self.state_status.value < progress:
            self.state_status.value = progress
            sys.stdout.write(
                "\r    " + self.SH_BG_YELLOW + "[" + ("#" * bar).ljust(self.columns - 11, "-") + "]" +
                self.SH_DEFAULT + ("%4s" % progress) + "%" + ("\n" if progress == 100 else "")
            )

    def done(self, epub_file):
        self.info("Done: %s\n\n" % epub_file +
                  "    If you like it, please * this project on GitHub to make it known:\n"
                  "        https://github.com/lorenzodifuccia/safaribooks\n"
                  "    e don't forget to renew your Safari Books Online subscription:\n"
                  "        " + config.SAFARI_BASE_URL + "\n\n" + # Use config
                  self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Bye!!")

    @staticmethod
    def api_error(response): # No changes needed here other than what was done in previous steps
        message = "API Error: "
        detail = response.get("detail", "")

        if "Not found" in detail:
            return f"{message}Book not found. Detail: {detail}. " \
                   "The book identifier is the digits that you can find in the URL: " \
                   f"`{config.SAFARI_BASE_URL}/library/view/book-name/XXXXXXXXXXXXX/`" # Use config

        if os.path.exists(COOKIES_FILE):
            try:
                os.remove(COOKIES_FILE)
                self.log(f"Removed {COOKIES_FILE} due to API error.")
            except OSError as e:
                self.log(f"Error removing {COOKIES_FILE}: {e}")
        
        # This will be raised as AuthenticationError or APIDataError
        return f"{message}Session or API issue. Detail: {detail}. " \
               "Try using `--cred` or `--login` options."

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Authenticator Class
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
class Authenticator:
    def __init__(self, http_client, display):
        self.http_client = http_client
        self.display = display
        self.jwt = {} # Store JWT tokens if obtained

    @staticmethod
    def parse_cred(cred_str): # Renamed from cred to cred_str to avoid confusion
        if ":" not in cred_str:
            # Consider raising ValueError for clearer error handling by the caller
            return False 

        sep = cred_str.index(":")
        new_cred = ["", ""]
        new_cred[0] = cred_str[:sep].strip("'").strip('"')
        if "@" not in new_cred[0]: # Basic email validation
            return False

        new_cred[1] = cred_str[sep + 1:]
        return new_cred

    def do_login(self, email, password):
        self.display.info("Attempting to log in...", state=True)
        try:
            response = self.http_client.get(config.LOGIN_ENTRY_URL)
        except NetworkConnectionError as e:
            raise AuthenticationError(f"Login failed: Unable to reach Safari Books Online. Network error: {e}") from e

        next_parameter = None
        try:
            parsed_url = urlparse(response.request.url) # type: ignore
            query_params = parse_qs(parsed_url.query)
            if "next" not in query_params or not query_params["next"]:
                 raise AuthenticationError("Login failed: 'next' parameter missing or empty in redirect URL.")
            next_parameter = query_params["next"][0]
        except (AttributeError, ValueError, IndexError, KeyError) as e: # Added KeyError
            raise AuthenticationError(f"Login failed: Unable to parse 'next' parameter from login redirect URL. Error: {e}")

        redirect_uri = config.API_ORIGIN_URL + quote_plus(next_parameter)

        try:
            response = self.http_client.post(
                config.LOGIN_URL,
                json_data={
                    "email": email,
                    "password": password,
                    "redirect_uri": redirect_uri
                },
                perform_redirect=False,
                expected_status_codes=[200] # Expect 200 for successful login POST
            )
        except NetworkConnectionError as e:
             raise AuthenticationError(f"Login failed: Auth request failed. Network error: {e}") from e
        except HttpRequestError as e: # Raised by HttpClient if status is not 200
            error_message = "Login failed: Unable to perform auth login to Safari Books Online."
            try:
                error_page = html.fromstring(e.response_text or "")
                errors_list = error_page.xpath("//ul[@class='errorlist']//li/text()")
                if any("password" in err.lower() or "email" in err.lower() for err in errors_list):
                    raise InvalidCredentialsError(f"{error_message} Details: {', '.join(errors_list)}") from e
                if error_page.xpath("//div[@class='g-recaptcha']"): # type: ignore
                    raise AuthenticationError(f"{error_message} ReCaptcha required.") from e
                
                if e.response_text:
                    json_response = json.loads(e.response_text)
                    if "detail" in json_response:
                         error_message += f" Detail: {json_response['detail']}"
                raise AuthenticationError(error_message) from e
            except (html.etree.ParseError, etree.ParserError, json.JSONDecodeError) as parsing_exc:
                # If parsing fails, the original HttpRequestError 'e' contains the necessary info.
                raise e from parsing_exc 

        try:
            self.jwt = response.json() # type: ignore
        except json.JSONDecodeError as e_json:
            raise APIDataError(f"Login failed: Failed to decode JWT JSON response: {e_json}. Response text: {response.text}") from e_json # type: ignore

        if "redirect_uri" not in self.jwt:
            raise APIDataError(f"Login failed: 'redirect_uri' not in JWT response. JWT: {self.jwt}")

        try:
            self.http_client.get(self.jwt["redirect_uri"]) # Follow final redirect
        except NetworkConnectionError as e_net:
            raise AuthenticationError(f"Login failed: Unable to reach Safari Books Online after JWT. Network error: {e_net}") from e_net
        
        self.display.info("Successfully logged in.", state=True)


    def check_login(self):
        self.display.info("Verifying session...", state=True)
        try:
            response = self.http_client.get(config.PROFILE_URL, perform_redirect=False, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise AuthenticationError(f"Session check failed: Unable to reach profile page. Network error: {e}") from e
        except HttpRequestError as e: # Raised if status code is not 200
            # More specific error for common auth failure cases
            if e.status_code == 401 or e.status_code == 403:
                 raise AuthenticationError(f"Session invalid or expired. Please log in again. Status: {e.status_code}") from e
            raise AuthenticationError(f"Session check failed: Unable to access profile page. Status: {e.status_code}") from e
        
        # Fragile check, but kept from original logic. Consider more robust validation if API allows.
        if "user_type\":\"Expired\"" in response.text: # type: ignore
            raise UserAccountError("Account subscription has expired.")
        self.display.info("Session is valid.", state=True)

    def load_cookies_from_file(self, cookie_file_path=COOKIES_FILE):
        if not os.path.isfile(cookie_file_path):
            # This is not necessarily an error if login via creds is an option.
            # Raising an error here might be too strict if called preemptively.
            # For now, let Display handle the message.
            self.display.info(f"Cookie file '{os.path.basename(cookie_file_path)}' not found. New session will be started if login credentials are provided.", state=True)
            return False # Indicate cookies were not loaded
        try:
            with open(cookie_file_path, 'r') as f:
                cookies = json.load(f)
                self.http_client.session.cookies.update(cookies)
            self.display.info(f"Cookies successfully loaded from '{os.path.basename(cookie_file_path)}'.", state=True)
            return True # Indicate cookies were loaded
        except (json.JSONDecodeError, OSError) as e:
            # Use display.error which also logs
            self.display.error(f"Error reading or parsing cookies from {cookie_file_path}: {e}")
            # It might be better to raise FileOperationError here if this is critical
            # raise FileOperationError(f"Error reading or parsing cookies from {cookie_file_path}: {e}") from e
            return False # Indicate cookies were not loaded

    def save_cookies_to_file(self, cookie_file_path=COOKIES_FILE):
        try:
            with open(cookie_file_path, 'w') as f:
                json.dump(self.http_client.session.cookies.get_dict(), f)
            self.display.info(f"Session cookies saved to '{os.path.basename(cookie_file_path)}'.", state=True)
        except OSError as e:
            self.display.error(f"Could not save cookies to {cookie_file_path}: {e}")
            # Consider raising FileOperationError if this is critical
            # raise FileOperationError(f"Could not save cookies to {cookie_file_path}: {e}") from e

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# End Authenticator Class
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

class WinQueue(list):
    def put(self, el):
        self.append(el)

    def qsize(self):
        return self.__len__()


class SafariBooks:
    BASE_01_HTML = "<!DOCTYPE html>\n" \
                   "<html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"" \
                   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" \
                   " xsi:schemaLocation=\"http://www.w3.org/2002/06/xhtml2/" \
                   " http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd\"" \
                   " xmlns:epub=\"http://www.idpf.org/2007/ops\">\n" \
                   "<head>\n" \
                   "{0}\n" \
                   "<style type=\"text/css\">" \
                   "body{{margin:1em;background-color:transparent!important;}}" \
                   "#sbo-rt-content *{{text-indent:0pt!important;}}#sbo-rt-content .bq{{margin-right:1em!important;}}"

    KINDLE_HTML = "#sbo-rt-content *{{word-wrap:break-word!important;" \
                  "word-break:break-word!important;}}#sbo-rt-content table,#sbo-rt-content pre" \
                  "{{overflow-x:unset!important;overflow:unset!important;" \
                  "overflow-y:unset!important;white-space:pre-wrap!important;}}"

    BASE_02_HTML = "</style>" \
                   "</head>\n" \
                   "<body>{1}</body>\n</html>"

    CONTAINER_XML = "<?xml version=\"1.0\"?>" \
                    "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" \
                    "<rootfiles>" \
                    "<rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\" />" \
                    "</rootfiles>" \
                    "</container>"

    # Format: ID, Title, Authors, Description, Subjects, Publisher, Rights, Date, CoverId, MANIFEST, SPINE, CoverUrl
    CONTENT_OPF = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
                  "<package xmlns=\"http://www.idpf.org/2007/opf\" unique-identifier=\"bookid\" version=\"2.0\" >\n" \
                  "<metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\" " \
                  " xmlns:opf=\"http://www.idpf.org/2007/opf\">\n" \
                  "<dc:title>{1}</dc:title>\n" \
                  "{2}\n" \
                  "<dc:description>{3}</dc:description>\n" \
                  "{4}" \
                  "<dc:publisher>{5}</dc:publisher>\n" \
                  "<dc:rights>{6}</dc:rights>\n" \
                  "<dc:language>en-US</dc:language>\n" \
                  "<dc:date>{7}</dc:date>\n" \
                  "<dc:identifier id=\"bookid\">{0}</dc:identifier>\n" \
                  "<meta name=\"cover\" content=\"{8}\"/>\n" \
                  "</metadata>\n" \
                  "<manifest>\n" \
                  "<item id=\"ncx\" href=\"toc.ncx\" media-type=\"application/x-dtbncx+xml\" />\n" \
                  "{9}\n" \
                  "</manifest>\n" \
                  "<spine toc=\"ncx\">\n{10}</spine>\n" \
                  "<guide><reference href=\"{11}\" title=\"Cover\" type=\"cover\" /></guide>\n" \
                  "</package>"

    # Format: ID, Depth, Title, Author, NAVMAP
    TOC_NCX = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>\n" \
              "<!DOCTYPE ncx PUBLIC \"-//NISO//DTD ncx 2005-1//EN\"" \
              " \"http://www.daisy.org/z3986/2005/ncx-2005-1.dtd\">\n" \
              "<ncx xmlns=\"http://www.daisy.org/z3986/2005/ncx/\" version=\"2005-1\">\n" \
              "<head>\n" \
              "<meta content=\"ID:ISBN:{0}\" name=\"dtb:uid\"/>\n" \
              "<meta content=\"{1}\" name=\"dtb:depth\"/>\n" \
              "<meta content=\"0\" name=\"dtb:totalPageCount\"/>\n" \
              "<meta content=\"0\" name=\"dtb:maxPageNumber\"/>\n" \
              "</head>\n" \
              "<docTitle><text>{2}</text></docTitle>\n" \
              "<docAuthor><text>{3}</text></docAuthor>\n" \
              "<navMap>{4}</navMap>\n" \
              "</ncx>"

    # HEADERS global removed. HttpClient will use config.DEFAULT_REQUEST_HEADERS.
    # COOKIE_FLOAT_MAX_AGE_PATTERN is in http_client.py, not needed here.

    def __init__(self, args, logger, log_file_path_for_display): # Accept logger and log_file_path
        self.args = args
        # The log_file_path_for_display is the one created in __main__
        # It's passed to Display for its own reference (e.g., if it needs to mention the log file name)
        # and to SafariBooks for the log removal logic.
        self.log_file_path = log_file_path_for_display 
        self.display = Display(logger, self.log_file_path)
        self.logger = logger # Keep a reference if SafariBooks methods need direct logging

        self.display.intro()

        self.http_client = HttpClient(
            base_headers=config.DEFAULT_REQUEST_HEADERS.copy(),
            proxies=config.PROXIES if config.USE_PROXY else None,
            verify_ssl=not config.USE_PROXY
        )
        self.display.http_client_ref = self.http_client 

        self.authenticator = Authenticator(self.http_client, self.display)
        
        # Authentication Flow
        if args.cred: # Handles --cred "email:pass" from main parsing
            self.authenticator.do_login(args.cred[0], args.cred[1]) # args.cred is [email, pass]
            if not args.no_cookies:
                self.authenticator.save_cookies_to_file(COOKIES_FILE)
        # args.login (prompt) is handled in __main__ before SafariBooks instantiation now.
        # If __main__ successfully gets creds via prompt, it puts them in args.cred.
        # So, if args.login was true and creds were obtained, the above `if args.cred:` block handles it.
        else: # No --cred or --login, try to load cookies
            loaded_cookies = self.authenticator.load_cookies_from_file(COOKIES_FILE)
            if not loaded_cookies:
                # If cookies not loaded, and no creds provided, it's an issue.
                self.display.error("No credentials provided and no valid cookie file found. Please use --cred or --login.")
                # Authenticator.exit calls Display.exit, which logs and then raises SafariBooksError
                self.display.exit("Authentication required.", self.http_client)


        self.authenticator.check_login()

        self.book_id = args.bookid
        # API_URL uses config.API_TEMPLATE
        self.api_url = config.API_TEMPLATE.format(self.book_id)

        self.display.info("Retrieving book info...")
        self.book_info = self.get_book_info()
        self.display.book_info(self.book_info)

        self.display.info("Retrieving book chapters...")
        self.book_chapters = self.get_book_chapters() # Can raise APIDataError

        self.chapters_queue = self.book_chapters[:]

        if len(self.book_chapters) > sys.getrecursionlimit():
            sys.setrecursionlimit(len(self.book_chapters))

        self.book_title = self.book_info["title"]
        self.base_url = self.book_info["web_url"]

        self.clean_book_title = "".join(self.escape_dirname(self.book_title).split(",")[:2]) \
                                + " ({0})".format(self.book_id)
        
        # books_dir uses config.DEFAULT_BOOKS_DIR_NAME and PATH
        books_dir_path = os.path.join(PATH, config.DEFAULT_BOOKS_DIR_NAME)
        if not os.path.isdir(books_dir_path):
            os.mkdir(books_dir_path)

        self.BOOK_PATH = os.path.join(books_dir_path, self.clean_book_title)
        self.display.set_output_dir(self.BOOK_PATH)
        self.css_path = ""
        self.images_path = ""
        self.create_dirs()

        self.chapter_title = ""
        self.filename = ""
        self.chapter_stylesheets = []
        self.css = []
        self.images = []

        self.display.info("Downloading book contents... (%s chapters)" % len(self.book_chapters), state=True)
        self.BASE_HTML = self.BASE_01_HTML + (self.KINDLE_HTML if not args.kindle else "") + self.BASE_02_HTML

        self.cover = False
        self.get()
        if not self.cover:
            if "cover" in self.book_info and self.book_info["cover"] != 'n/a':
                self.cover = self.get_default_cover() # Can raise NetworkConnectionError, FileOperationError
            else:
                self.cover = False # No cover in book_info or it's 'n/a'
            
            if self.cover: # Proceed only if a cover was successfully fetched or is available
                try:
                    cover_html_content = f"<div id=\"sbo-rt-content\"><img src=\"Images/{self.cover}\"></div>"
                    cover_element = html.fromstring(cover_html_content)
                    parsed_cover_html = self.parse_html(cover_element, True) # Can raise ParsingError
                except etree.ParserError as e:
                    raise ParsingError(f"Failed to parse default cover HTML: {e}") from e
                
                # self.parse_html can raise APIDataError if it encounters an API error during parsing,
                # though less likely for a simple static HTML string like the above.

                self.book_chapters = [{
                    "filename": "default_cover.xhtml",
                    "title": "Cover"
                }] + self.book_chapters

                self.filename = self.book_chapters[0]["filename"]
                self.save_page_html(parsed_cover_html) # Can raise FileOperationError
            else:
                self.display.info("No default cover found or 'cover' not in book_info.")


            self.book_chapters = [{
                "filename": "default_cover.xhtml",
                "title": "Cover"
            }] + self.book_chapters

            self.filename = self.book_chapters[0]["filename"]
            self.save_page_html(cover_html)

        self.css_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book CSSs... (%s files)" % len(self.css), state=True)
        self.collect_css()
        self.images_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book images... (%s files)" % len(self.images), state=True)
        self.collect_images()

        self.display.info("Creating EPUB file...", state=True)
        self.create_epub() # Can raise FileOperationError

        if not args.no_cookies:
            try:
                with open(COOKIES_FILE, "w") as f:
                    json.dump(self.http_client.session.cookies.get_dict(), f)
            except OSError as e:
                self.display.error(f"Could not save cookies to {COOKIES_FILE} at the end: {e}") # Display.error uses logger

        self.display.done(os.path.join(self.BOOK_PATH, self.book_id + ".epub"))
        self.display.unregister() # Display.unregister is simplified

        # Log file removal logic
        if not self.display.in_error and not args.log: # args.log is from argparse
            try:
                # Close all handlers for this logger before removing the file
                for handler in self.logger.handlers[:]: # Iterate over a copy
                    if isinstance(handler, logging.FileHandler) and handler.baseFilename == self.log_file_path:
                        handler.close()
                        self.logger.removeHandler(handler)
                
                if os.path.exists(self.log_file_path):
                    os.remove(self.log_file_path)
                    # Log removal to console via Display.out or a new simple print, as logger's file handler is gone
                    # Or, have a separate console logger if general log messages are desired on console.
                    # For now, let's assume this is a silent operation on success.
            except OSError as e:
                # If removal fails, log to console via Display.error (which also logs to any *other* handlers if present)
                self.display.error(f"Could not remove log file {self.log_file_path}: {e}")

    @staticmethod
    @staticmethod # Moved from SafariBooks to Authenticator, then here as it's used in __main__
    def parse_cred(cred_str):
        if ":" not in cred_str:
            return False 
        sep = cred_str.index(":")
        new_cred = ["", ""]
        new_cred[0] = cred_str[:sep].strip("'").strip('"')
        if "@" not in new_cred[0]:
            return False
        new_cred[1] = cred_str[sep + 1:]
        return new_cred

    # Placeholder for get_book_info until SafariAPIClient is created
    def get_book_info(self):
        try:
            # Use HttpClient, expected_status_codes ensures 200.
            response = self.http_client.get(self.api_url, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise APIDataError(f"API: unable to retrieve book info due to network error: {e}") from e
        except HttpRequestError as e: # If status not 200
            # Attempt to parse error response for specific conditions
            try:
                json_err_response = json.loads(e.response_text or "{}")
                error_detail = self.display.api_error(json_err_response) # This returns a string
                if "Not found" in error_detail:
                    raise BookNotFoundError(error_detail) from e
                else: # Could be auth error if cookies expired
                    raise AuthenticationError(error_detail) from e
            except json.JSONDecodeError: # If response is not JSON
                raise APIDataError(f"API: Failed to retrieve book info. Status: {e.status_code}. Non-JSON Response: {e.response_text}") from e


        try:
            json_response = response.json() # type: ignore
        except json.JSONDecodeError as e:
            raise APIDataError(f"API: Failed to decode book info JSON. Error: {e}. Response text: {response.text}") from e

        # The original check `len(json_response.keys()) == 1` was part of the error condition.
        # This is now implicitly handled by HttpRequestError if the server gives non-200 for such cases.
        # If it's a 200 response but malformed, json.JSONDecodeError or subsequent logic handles it.

        if "last_chapter_read" in json_response: # json_response is already a dict here
            del json_response["last_chapter_read"]

        for key, value in json_response.items():
            if value is None:
                json_response[key] = 'n/a'

        return json_response

    def get_book_chapters(self, page=1):
        url = urljoin(self.api_url, f"chapter/?page={page}")
        try:
            response = self.http_client.get(url, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise APIDataError(f"API: unable to retrieve book chapters (page {page}) due to network error: {e}") from e
        except HttpRequestError as e: # Non-200 status
            try:
                json_err_response = json.loads(e.response_text or "{}")
                error_detail = self.display.api_error(json_err_response)
                if "Not found" in error_detail:
                    raise BookNotFoundError(error_detail) from e
                else:
                    raise AuthenticationError(error_detail) from e # Or APIDataError
            except json.JSONDecodeError:
                 raise APIDataError(f"API: Failed to retrieve book chapters (page {page}). Status: {e.status_code}. Non-JSON: {e.response_text}") from e


        try:
            json_response = response.json() # type: ignore
        except json.JSONDecodeError as e_json:
            raise APIDataError(f"API: Failed to decode book chapters JSON (page {page}). Error: {e_json}. Response text: {response.text}") from e_json # type: ignore


        if not isinstance(json_response, dict) or "results" not in json_response:
            # This case implies a 200 OK but unexpected JSON structure.
            raise APIDataError(f"API: Unexpected structure in book chapters response (page {page}). 'results' missing. Got: {json_response}")


        if not json_response["results"]:
            # This could be a valid empty list if a book has no chapters, or an error.
            # The original code treated this as an error.
            # If an empty result is possible and valid, this should be handled differently.
            # For now, maintaining original behavior of treating as error.
            self.display.info(f"API: No chapters found in 'results' for page {page}. This might be an error or an empty book section.")
            # Depending on strictness, could raise APIDataError here.
            # If an empty list of chapters is a hard error:
            # raise APIDataError(f"API: No chapters found in 'results' for book (page {page}).")


        if json_response.get("count", 0) > sys.getrecursionlimit():
            sys.setrecursionlimit(json_response["count"])

        result = []
        # Filter cover pages first
        result.extend([c for c in json_response["results"] if "cover" in c.get("filename", "") or "cover" in c.get("title", "")])
        
        # Add remaining chapters, ensuring no duplicates if they were already added as covers
        # This requires a more careful way to remove items if `response["results"]` was a list of dicts.
        # For simplicity, let's assume `results` are chapters and covers are distinct items or handled by ordering.
        # A safer way is to build a set of added chapter IDs if chapters have unique IDs.
        # current_results_excluding_covers = [c for c in json_response["results"] if c not in result]
        # result.extend(current_results_excluding_covers)
        # The original logic was:
        # result.extend([c for c in response["results"] if "cover" in c["filename"] or "cover" in c["title"]])
        # for c in result: del response["results"][response["results"].index(c)]
        # result += response["results"]
        # This is complex due to modifying list while iterating implicitly.
        # A cleaner approach:
        non_cover_chapters = [c for c in json_response["results"] if not ("cover" in c.get("filename", "") or "cover" in c.get("title", ""))]
        result.extend(non_cover_chapters)


        return result + (self.get_book_chapters(page + 1) if json_response.get("next") else [])

    def get_default_cover(self):
        cover_url = self.book_info.get("cover")
        if not cover_url or cover_url == 'n/a':
            self.display.info("No cover URL available in book_info.")
            return False
        try:
            # Use HttpClient, pass stream=True. Expected status 200.
            response = self.http_client.get(cover_url, stream=True, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise NetworkConnectionError(f"Error retrieving the cover {cover_url}: {e}") from e
        except HttpRequestError as e: # Non-200 status
            raise HttpRequestError(f"Failed to download cover {cover_url}. Status: {e.status_code}",
                                   status_code=e.status_code, response_text=e.response_text) from e
        # No response == 0 check

        file_ext = response.headers.get("Content-Type", "image/jpeg").split("/")[-1] # Default to jpeg if not found. Response is from http_client.
        cover_filename = "default_cover." + file_ext
        cover_filepath = os.path.join(self.images_path, cover_filename)
        try:
            with open(cover_filepath, 'wb') as i:
                for chunk in response.iter_content(1024):
                    i.write(chunk)
        except OSError as e:
            raise FileOperationError(f"Error writing cover image to {cover_filepath}: {e}") from e

        return cover_filename

    def get_html(self, url):
        try:
            # Use HttpClient. Expected status 200.
            response = self.http_client.get(url, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise HttpRequestError( # Keep HttpRequestError for consistency if this is what callers expect
                f"Crawler: network error trying to retrieve page: {self.filename} ({self.chapter_title}) from {url}. Error: {e}",
                response_text=str(e)
            ) from e
        except HttpRequestError as e: # Non-200 status
             raise HttpRequestError(
                f"Crawler: error trying to retrieve page: {self.filename} ({self.chapter_title})\n    From: {url}. Status: {e.status_code}",
                status_code=e.status_code, response_text=e.response_text
            ) from e
        # No response == 0 check

        try:
            root = html.fromstring(response.text, base_url=config.SAFARI_BASE_URL) # type: ignore # Use config
        except (etree.ParseError, etree.ParserError) as parsing_error:
            raise ParsingError(
                f"Crawler: error trying to parse page: {self.filename} ({self.chapter_title})\n    From: {url}\n    Error: {parsing_error}"
            ) from parsing_error

        return root

    @staticmethod
    def url_is_absolute(url):
        return bool(urlparse(url).netloc)

    @staticmethod
    def is_image_link(url: str):
        return pathlib.Path(url).suffix[1:].lower() in ["jpg", "jpeg", "png", "gif"]

    def link_replace(self, link):
        if link and not link.startswith("mailto"):
            if not self.url_is_absolute(link):
                if any(x in link for x in ["cover", "images", "graphics"]) or \
                        self.is_image_link(link):
                    image = link.split("/")[-1]
                    return "Images/" + image

                return link.replace(".html", ".xhtml")

            else:
                if self.book_id in link:
                    return self.link_replace(link.split(self.book_id)[-1])

        return link

    @staticmethod
    def get_cover(html_root):
        lowercase_ns = etree.FunctionNamespace(None)
        lowercase_ns["lower-case"] = lambda _, n: n[0].lower() if n and len(n) else ""

        images = html_root.xpath("//img[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                                 "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover') or"
                                 "contains(lower-case(@alt), 'cover')]")
        if len(images):
            return images[0]

        divs = html_root.xpath("//div[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                               "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(divs):
            return divs[0]

        a = html_root.xpath("//a[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                            "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(a):
            return a[0]

        return None

    def parse_html(self, root, first_page=False):
        # This check seems like a heuristic for detecting expired sessions or unexpected page structures.
        # It might be better to rely on more direct error indicators if possible.
        # For now, translate it to an APIDataError if it triggers.
        if random() > 0.8: # This random check is problematic for deterministic error handling.
            # Consider removing or making it more specific if it's trying to catch a particular issue.
            # If it's for detecting unexpected content (like a login page), a more robust check is needed.
            control_text = root.xpath("//div[@class='controls']/a/text()")
            if control_text:
                # self.display.api_error(" ") would be "API Error: Session or API issue. Detail: . Try using..."
                raise APIDataError(f"Parser: Detected unexpected controls text ('{control_text}'), possibly indicating session or API issue for {self.filename} ({self.chapter_title}).")

        book_content_elements = root.xpath("//div[@id='sbo-rt-content']")
        if not book_content_elements:
            # Check if it's due to a known error page structure
            error_messages = root.xpath("//div[contains(@class, 'error-summary') or contains(@class, 'message-error')]/descendant-or-self::*/text()")
            if error_messages:
                full_error_text = ' '.join(text.strip() for text in error_messages if text.strip())
                raise APIDataError(
                    f"Parser: Server-side error message found on page {self.filename} ({self.chapter_title}): {full_error_text}"
                )
            # If no specific error message, but content is missing
            raise ParsingError(
                f"Parser: book content ('sbo-rt-content') not found or empty on page: {self.filename} ({self.chapter_title}). Page structure might have changed."
            )

        page_css = ""
        book_content = book_content_elements[0] # Use the first match
        if len(self.chapter_stylesheets):
            for chapter_css_url in self.chapter_stylesheets:
                if chapter_css_url not in self.css:
                    self.css.append(chapter_css_url)
                    self.display.log("Crawler: found a new CSS at %s" % chapter_css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(chapter_css_url))

        stylesheet_links = root.xpath("//link[@rel='stylesheet']")
        if len(stylesheet_links):
            for s in stylesheet_links:
                css_url = urljoin("https:", s.attrib["href"]) if s.attrib["href"][:2] == "//" \
                    else urljoin(self.base_url, s.attrib["href"])

                if css_url not in self.css:
                    self.css.append(css_url)
                    self.display.log("Crawler: found a new CSS at %s" % css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(css_url))

        stylesheets = root.xpath("//style")
        if len(stylesheets):
            for css in stylesheets:
                if "data-template" in css.attrib and len(css.attrib["data-template"]):
                    css.text = css.attrib["data-template"]
                    del css.attrib["data-template"]

                try:
                    page_css += html.tostring(css, method="xml", encoding='unicode') + "\n"

                except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                    # self.display.error(parsing_error) # Logged by unhandled_exception if it bubbles up
                    raise ParsingError(
                        f"Parser: error trying to parse one inline CSS found in this page: {self.filename} ({self.chapter_title}). Error: {parsing_error}"
                    ) from parsing_error

        # TODO: add all not covered tag for `link_replace` function
        svg_image_tags = root.xpath("//image")
        if len(svg_image_tags):
            for img in svg_image_tags:
                image_attr_href = [x for x in img.attrib.keys() if "href" in x]
                if len(image_attr_href):
                    svg_url = img.attrib.get(image_attr_href[0])
                    svg_root = img.getparent().getparent()
                    new_img = svg_root.makeelement("img")
                    new_img.attrib.update({"src": svg_url})
                    svg_root.remove(img.getparent())
                    svg_root.append(new_img)

        book_content = book_content[0]
        book_content.rewrite_links(self.link_replace)

        xhtml = None
        try:
            if first_page:
                is_cover = self.get_cover(book_content)
                if is_cover is not None:
                    page_css = "<style>" \
                               "body{display:table;position:absolute;margin:0!important;height:100%;width:100%;}" \
                               "#Cover{display:table-cell;vertical-align:middle;text-align:center;}" \
                               "img{height:90vh;margin-left:auto;margin-right:auto;}" \
                               "</style>"
                    cover_html = html.fromstring("<div id=\"Cover\"></div>")
                    cover_div = cover_html.xpath("//div")[0]
                    cover_img = cover_div.makeelement("img")
                    cover_img.attrib.update({"src": is_cover.attrib["src"]})
                    cover_div.append(cover_img)
                    book_content = cover_html

                    self.cover = is_cover.attrib["src"]

            xhtml = html.tostring(book_content, method="xml", encoding='unicode')

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            # self.display.error(parsing_error) # Logged by unhandled_exception
            raise ParsingError(
                f"Parser: error trying to convert HTML content to string for page: {self.filename} ({self.chapter_title}). Error: {parsing_error}"
            ) from parsing_error

        return page_css, xhtml

    @staticmethod
    def escape_dirname(dirname, clean_space=False):
        if ":" in dirname:
            if dirname.index(":") > 15:
                dirname = dirname.split(":")[0]

            elif "win" in sys.platform:
                dirname = dirname.replace(":", ",")

        for ch in ['~', '#', '%', '&', '*', '{', '}', '\\', '<', '>', '?', '/', '`', '\'', '"', '|', '+', ':']:
            if ch in dirname:
                dirname = dirname.replace(ch, "_")

        return dirname if not clean_space else dirname.replace(" ", "")

    def create_dirs(self):
        if os.path.isdir(self.BOOK_PATH):
            self.display.log("Book directory already exists: %s" % self.BOOK_PATH)

        else:
            os.makedirs(self.BOOK_PATH)

        oebps = os.path.join(self.BOOK_PATH, "OEBPS")
        if not os.path.isdir(oebps):
            self.display.book_ad_info = True
            os.makedirs(oebps)

        self.css_path = os.path.join(oebps, "Styles")
        if os.path.isdir(self.css_path):
            self.display.log("CSSs directory already exists: %s" % self.css_path)

        else:
            os.makedirs(self.css_path)
            self.display.css_ad_info.value = 1

        self.images_path = os.path.join(oebps, "Images")
        if os.path.isdir(self.images_path):
            self.display.log("Images directory already exists: %s" % self.images_path)

        else:
            os.makedirs(self.images_path)
            self.display.images_ad_info.value = 1

    def save_page_html(self, contents):
        self.filename = self.filename.replace(".html", ".xhtml")
        filepath = os.path.join(self.BOOK_PATH, "OEBPS", self.filename)
        try:
            with open(filepath, "wb") as f:
                f.write(self.BASE_HTML.format(contents[0], contents[1]).encode("utf-8", 'xmlcharrefreplace'))
            self.display.log("Created: %s" % self.filename)
        except OSError as e:
            raise FileOperationError(f"Failed to write HTML file {filepath}: {e}") from e
        except Exception as e: # Catch potential formatting errors, though less likely with encode
            raise SafariBooksError(f"An unexpected error occurred saving page {filepath}: {e}")


    def get(self):
        len_books = len(self.book_chapters)

        for _ in range(len_books):
            if not len(self.chapters_queue):
                return

            first_page = len_books == len(self.chapters_queue)

            next_chapter = self.chapters_queue.pop(0)
            self.chapter_title = next_chapter["title"]
            self.filename = next_chapter["filename"]

            asset_base_url = next_chapter['asset_base_url']
            api_v2_detected = False
            if 'v2' in next_chapter['content']:
                # asset_base_url uses config.SAFARI_BASE_URL
                asset_base_url = config.SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{}/files".format(self.book_id)
                api_v2_detected = True

            if "images" in next_chapter and len(next_chapter["images"]):
                for img_url in next_chapter['images']:
                    if api_v2_detected:
                        self.images.append(asset_base_url + '/' + img_url)
                    else:
                        self.images.append(urljoin(next_chapter['asset_base_url'], img_url))


            # Stylesheets
            self.chapter_stylesheets = []
            if "stylesheets" in next_chapter and len(next_chapter["stylesheets"]):
                self.chapter_stylesheets.extend(x["url"] for x in next_chapter["stylesheets"])

            if "site_styles" in next_chapter and len(next_chapter["site_styles"]):
                self.chapter_stylesheets.extend(next_chapter["site_styles"])

            if os.path.isfile(os.path.join(self.BOOK_PATH, "OEBPS", self.filename.replace(".html", ".xhtml"))):
                if not self.display.book_ad_info and \
                        next_chapter not in self.book_chapters[:self.book_chapters.index(next_chapter)]:
                    self.display.info(
                        ("File `%s` already exists.\n"
                         "    If you want to download again all the book,\n"
                         "    please delete the output directory '" + self.BOOK_PATH + "' and restart the program.")
                         % self.filename.replace(".html", ".xhtml")
                    )
                    self.display.book_ad_info = 2

            else:
                # These can raise HttpRequestError, ParsingError, APIDataError
                html_content = self.get_html(next_chapter["content"])
                parsed_content = self.parse_html(html_content, first_page)
                self.save_page_html(parsed_content) # Can raise FileOperationError

            self.display.state(len_books, len_books - len(self.chapters_queue))

    def _thread_download_css(self, url):
        css_file = os.path.join(self.css_path, "Style{0:0>2}.css".format(self.css.index(url)))
        if os.path.isfile(css_file):
            if not self.display.css_ad_info.value and url not in self.css[:self.css.index(url)]: # type: ignore
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the CSSs,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  css_file)
                self.display.css_ad_info.value = 1 # type: ignore

        else:
            try:
                # Use HttpClient. Expected status 200.
                response = self.http_client.get(url, expected_status_codes=[200])
                with open(css_file, 'wb') as s:
                    s.write(response.content) # type: ignore
            except NetworkConnectionError as e:
                self.display.error(f"Network error retrieving CSS {css_file} from {url}: {e}")
            except HttpRequestError as e: # Non-200 status
                self.display.error(f"HTTP error {e.status_code} retrieving CSS {css_file} from {url}: {e.response_text}")
            except FileOperationError as e: # From open/write
                 self.display.error(f"File error for CSS {css_file}: {e}")


        self.css_done_queue.put(1) # type: ignore
        self.display.state(len(self.css), self.css_done_queue.qsize())


    def _thread_download_images(self, url):
        image_name = url.split("/")[-1]
        image_path = os.path.join(self.images_path, image_name)
        if os.path.isfile(image_path):
            if not self.display.images_ad_info.value and url not in self.images[:self.images.index(url)]: # type: ignore
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the images,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  image_name)
                self.display.images_ad_info.value = 1 # type: ignore

        else:
            try:
                # urljoin uses config.SAFARI_BASE_URL
                response = self.http_client.get(urljoin(config.SAFARI_BASE_URL, url), stream=True, expected_status_codes=[200])
                with open(image_path, 'wb') as img:
                    for chunk in response.iter_content(1024): # type: ignore
                        img.write(chunk)
            except NetworkConnectionError as e:
                self.display.error(f"Network error retrieving image {image_name} from {url}: {e}")
            except HttpRequestError as e: # Non-200 status
                 self.display.error(f"HTTP error {e.status_code} retrieving image {image_name} from {url}: {e.response_text}")
            except FileOperationError as e: # From open/write
                 self.display.error(f"File error for image {image_path}: {e}")
            except Exception as e: # Catch any other unexpected errors during image download
                self.display.error(f"Unexpected error downloading image {image_name}: {e}")


        self.images_done_queue.put(1) # type: ignore
        self.display.state(len(self.images), self.images_done_queue.qsize())

    def _start_multiprocessing(self, operation, full_queue):
        if len(full_queue) > 5:
            for i in range(0, len(full_queue), 5):
                self._start_multiprocessing(operation, full_queue[i:i + 5])

        else:
            process_queue = [Process(target=operation, args=(arg,)) for arg in full_queue]
            for proc in process_queue:
                proc.start()

            for proc in process_queue:
                proc.join()

    def collect_css(self):
        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for css_url in self.css:
            self._thread_download_css(css_url)

    def collect_images(self):
        if self.display.book_ad_info == 2:
            self.display.info("Some of the book contents were already downloaded.\n"
                              "    If you want to be sure that all the images will be downloaded,\n"
                              "    please delete the output directory '" + self.BOOK_PATH +
                              "' and restart the program.")

        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for image_url in self.images:
            self._thread_download_images(image_url)

    def create_content_opf(self):
        self.css = next(os.walk(self.css_path))[2]
        self.images = next(os.walk(self.images_path))[2]

        manifest = []
        spine = []
        for c in self.book_chapters:
            c["filename"] = c["filename"].replace(".html", ".xhtml")
            item_id = escape("".join(c["filename"].split(".")[:-1]))
            manifest.append("<item id=\"{0}\" href=\"{1}\" media-type=\"application/xhtml+xml\" />".format(
                item_id, c["filename"]
            ))
            spine.append("<itemref idref=\"{0}\"/>".format(item_id))

        for i in set(self.images):
            dot_split = i.split(".")
            head = "img_" + escape("".join(dot_split[:-1]))
            extension = dot_split[-1]
            manifest.append("<item id=\"{0}\" href=\"Images/{1}\" media-type=\"image/{2}\" />".format(
                head, i, "jpeg" if "jp" in extension else extension
            ))

        for i in range(len(self.css)):
            manifest.append("<item id=\"style_{0:0>2}\" href=\"Styles/Style{0:0>2}.css\" "
                            "media-type=\"text/css\" />".format(i))

        authors = "\n".join("<dc:creator opf:file-as=\"{0}\" opf:role=\"aut\">{0}</dc:creator>".format(
            escape(aut.get("name", "n/d"))
        ) for aut in self.book_info.get("authors", []))

        subjects = "\n".join("<dc:subject>{0}</dc:subject>".format(escape(sub.get("name", "n/d")))
                             for sub in self.book_info.get("subjects", []))

        return self.CONTENT_OPF.format(
            (self.book_info.get("isbn",  self.book_id)),
            escape(self.book_title),
            authors,
            escape(self.book_info.get("description", "")),
            subjects,
            ", ".join(escape(pub.get("name", "")) for pub in self.book_info.get("publishers", [])),
            escape(self.book_info.get("rights", "")),
            self.book_info.get("issued", ""),
            self.cover,
            "\n".join(manifest),
            "\n".join(spine),
            self.book_chapters[0]["filename"].replace(".html", ".xhtml")
        )

    @staticmethod
    def parse_toc(l, c=0, mx=0):
        r = ""
        for cc in l:
            c += 1
            if int(cc["depth"]) > mx:
                mx = int(cc["depth"])

            r += "<navPoint id=\"{0}\" playOrder=\"{1}\">" \
                 "<navLabel><text>{2}</text></navLabel>" \
                 "<content src=\"{3}\"/>".format(
                    cc["fragment"] if len(cc["fragment"]) else cc["id"], c,
                    escape(cc["label"]), cc["href"].replace(".html", ".xhtml").split("/")[-1]
                 )

            if cc["children"]:
                sr, c, mx = SafariBooks.parse_toc(cc["children"], c, mx)
                r += sr

            r += "</navPoint>\n"

        return r, c, mx

    def create_toc(self):
        url = urljoin(self.api_url, "toc/")
        try:
            # Use HttpClient. Expected status 200.
            response = self.http_client.get(url, expected_status_codes=[200])
        except NetworkConnectionError as e:
            raise APIDataError(f"API: unable to retrieve book TOC due to network error: {e}. "
                               "EPUB creation might be incomplete.") from e
        except HttpRequestError as e: # Non-200 status
            try:
                json_err_response = json.loads(e.response_text or "{}")
                error_detail = self.display.api_error(json_err_response)
                if "Not found" in error_detail:
                    raise BookNotFoundError(f"{error_detail} Cannot create TOC.") from e
                else:
                    raise AuthenticationError(f"{error_detail} Cannot create TOC.") from e # Or APIDataError
            except json.JSONDecodeError:
                 raise APIDataError(f"API: Failed to retrieve TOC. Status: {e.status_code}. Non-JSON: {e.response_text}") from e

        try:
            json_response = response.json() # type: ignore
        except json.JSONDecodeError as e_json:
            raise APIDataError(f"API: Failed to decode book TOC JSON. Error: {e_json}. Response text: {response.text}. " # type: ignore
                               "EPUB creation might be incomplete.") from e_json

        # Original check: if not isinstance(response, list) and len(response.keys()) == 1:
        # This needs to be adapted for json_response.
        if not isinstance(json_response, list):
            if isinstance(json_response, dict) and len(json_response.keys()) == 1:
                # This was the original condition for an error from self.display.api_error
                error_detail = self.display.api_error(json_response)
                if "Not found" in error_detail:
                     raise BookNotFoundError(f"{error_detail} Cannot create TOC. (Malformed list response)")
                else:
                     raise AuthenticationError(f"{error_detail} Cannot create TOC. (Malformed list response)")
            else:
                # If it's not a list and not the specific dict case, it's an unexpected structure
                raise APIDataError(f"API: TOC response is not a list as expected. Got: {type(json_response)}")


        navmap, _, max_depth = self.parse_toc(json_response) # Pass json_response
        return self.TOC_NCX.format(
            (self.book_info["isbn"] if self.book_info["isbn"] else self.book_id),
            max_depth,
            self.book_title,
            ", ".join(aut.get("name", "") for aut in self.book_info.get("authors", [])),
            navmap
        )

    def create_epub(self):
        try:
            with open(os.path.join(self.BOOK_PATH, "mimetype"), "w") as f:
                f.write("application/epub+zip")
            
            meta_info = os.path.join(self.BOOK_PATH, "META-INF")
            if not os.path.isdir(meta_info):
                os.makedirs(meta_info)

            with open(os.path.join(meta_info, "container.xml"), "wb") as f:
                f.write(self.CONTAINER_XML.encode("utf-8", "xmlcharrefreplace"))
            
            with open(os.path.join(self.BOOK_PATH, "OEBPS", "content.opf"), "wb") as f:
                f.write(self.create_content_opf().encode("utf-8", "xmlcharrefreplace")) # Can raise APIDataError from create_toc
            
            with open(os.path.join(self.BOOK_PATH, "OEBPS", "toc.ncx"), "wb") as f:
                f.write(self.create_toc().encode("utf-8", "xmlcharrefreplace")) # Can raise APIDataError

            zip_file_base = os.path.join(PATH, "Books", self.book_id) # Base name for zip, before .zip extension
            zip_file_with_ext = zip_file_base + ".zip"
            epub_final_path = os.path.join(self.BOOK_PATH, self.book_id + ".epub")

            if os.path.isfile(zip_file_with_ext):
                os.remove(zip_file_with_ext)
            
            shutil.make_archive(zip_file_base, 'zip', self.BOOK_PATH)
            os.rename(zip_file_with_ext, epub_final_path)

        except OSError as e:
            raise FileOperationError(f"File operation failed during EPUB creation: {e}") from e
        except APIDataError: # Re-raise if create_toc or create_content_opf fails
            raise
        except Exception as e: # Catch-all for unexpected errors during EPUB creation
            raise SafariBooksError(f"An unexpected error occurred during EPUB creation: {e}") from e


# MAIN
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
             " `" + config.SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`" # Use config
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

    # Setup logger
    logger = logging.getLogger("SafariBooksApp")
    log_level_str = config.LOG_LEVEL.upper()
    log_level_int = getattr(logging, log_level_str, logging.INFO) # Default to INFO if parsing fails
    if not isinstance(log_level_int, int): # Check if getattr returned a string (e.g. LOG_LEVEL = "info")
        print(f"Warning: Invalid LOG_LEVEL '{config.LOG_LEVEL}'. Defaulting to INFO.", file=sys.stderr)
        log_level_int = logging.INFO
    logger.setLevel(log_level_int)

    # This is the definitive log_file_path for this run.
    # It's created here and passed to SafariBooks, which then passes it to Display.
    # This ensures all components know the correct log file path for operations like deletion.
    current_log_file_path = os.path.join(PATH, f"{config.DEFAULT_LOG_FILE_PREFIX}{escape(args_parsed.bookid)}.log")
    
    file_handler = logging.FileHandler(filename=current_log_file_path)
    formatter = logging.Formatter(fmt=config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Simplified global exception hook:
    # It logs the exception and then re-raises it, letting Python's default mechanism print it to stderr and exit.
    # Or, for more control, it could print a custom message and sys.exit().
    def global_exception_handler_with_logging(exc_type, exc_value, tb_obj):
        logger.critical("Global Unhandled Exception caught by sys.excepthook:", exc_info=(exc_type, exc_value, tb_obj))
        # Default Python excepthook will print to stderr and exit.
        # To customize, uncomment below and remove original_excepthook call:
        # print(f"A critical unhandled error occurred via excepthook: {exc_value}. Check logs.", file=sys.stderr)
        # sys.exit(3) # Different exit code
        sys.__excepthook__(exc_type, exc_value, tb_obj) # Call original excepthook

    sys.excepthook = global_exception_handler_with_logging
    
    safari_instance = None
    try:
        # Pass logger and the definitive log_file_path to SafariBooks
        safari_instance = SafariBooks(args_parsed, logger, current_log_file_path)
    except SafariBooksError as e:
        # Display.exit, called from within SafariBooks, handles UI & logging the error.
        # This block ensures the script exits with 1 for controlled SafariBooks errors.
        # The logger would have already captured the error details via Display.error -> Display.exit.
        sys.exit(1)
    except Exception as e: 
        # For truly unexpected errors not originating from SafariBooksError
        # and potentially before Display's error handling is involved, or if Display.exit wasn't called.
        logger.critical("An unexpected error occurred during main execution:", exc_info=True)
        print(f"An unexpected critical error occurred: {e}. Check logs for details.", file=sys.stderr)
        sys.exit(1) # General error exit code
        
    # Hint: do you want to download more then one book once, initialized more than one instance of `SafariBooks`...
    sys.exit(0)
