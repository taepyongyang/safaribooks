import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter, deque
from html import escape
from queue import Queue
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from lxml import etree, html

from safaribooks_config import (
    API_ORIGIN_HOST,
    API_ORIGIN_URL,
    COOKIES_FILE,
    ORLY_BASE_HOST,
    ORLY_BASE_URL,
    PATH,
    PROFILE_URL,
    PROXIES,
    SAFARI_BASE_HOST,
    SAFARI_BASE_URL,
    USE_PROXY,
)
from safaribooks_display import Display
from safaribooks_winqueue import WinQueue
from safaribooks_diagnostics import DiagnosticCollector, FailureCategory
from safaribooks_browser_auth import browser_login
from safaribooks_browser_transport import BrowserTransport

# HTTP timeout for all requests (prevents infinite hanging)
REQUESTS_TIMEOUT = 30  # seconds


class SafariBooks:
    """
    Main class for SafariBooks downloader and EPUB generator.
    Handles authentication, session management, book info retrieval, content downloading,
    HTML parsing, and EPUB file creation.
    """
    LOGIN_URL = ORLY_BASE_URL + "/member/auth/login/"
    LOGIN_ENTRY_URL = SAFARI_BASE_URL + "/login/unified/?next=/home/"

    # V2 API endpoints (v1 retired, returns 404 for all books)
    API_V2_EPUBS    = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/"
    API_V2_CHAPTERS = SAFARI_BASE_URL + "/api/v2/epub-chapters/?epub_identifier=urn:orm:book:{0}&limit=100&offset={1}"
    API_V2_TOC      = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/table-of-contents/"
    API_V2_SEARCH   = SAFARI_BASE_URL + "/api/v2/search/?query={0}&limit=1"
    API_V2_FILES    = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/files"

    BASE_01_HTML = "<!DOCTYPE html>\n" \
                   "<html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"" \
                   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" \
                   " xsi:schemaLocation=\"http://www.w3.org/2002/06/xhtml2/" \
                   " http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd\"" \
                   " xmlns:epub=\"http://www.idpf.org/2007/ops\">\n" \
                   "<head>\n" \
                   "<title></title>\n" \
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

    CONTAINER_XML = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" \
                    "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" \
                    "<rootfiles>" \
                    "<rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\" />" \
                    "</rootfiles>" \
                    "</container>"

    # Format: ID, Title, Authors, Description, Subjects, Publisher, Rights, Date, CoverMeta, MANIFEST, SPINE, CoverUrl, Language
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
                  "<dc:language>{12}</dc:language>\n" \
                  "<dc:date>{7}</dc:date>\n" \
                  "<dc:identifier id=\"bookid\">{0}</dc:identifier>\n" \
                  "{8}" \
                  "</metadata>\n" \
                  "<manifest>\n" \
                  "<item id=\"ncx\" href=\"toc.ncx\" media-type=\"application/x-dtbncx+xml\" />\n" \
                  "{9}\n" \
                  "</manifest>\n" \
                  "<spine toc=\"ncx\">\n{10}</spine>\n" \
                  "<guide><reference href=\"{11}\" title=\"Cover\" type=\"cover\" /></guide>\n" \
                  "</package>"

    # Format: ID, Depth, Title, Author, NAVMAP
    TOC_NCX = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
              "<!DOCTYPE ncx PUBLIC \"-//NISO//DTD ncx 2005-1//EN\"" \
              " \"http://www.daisy.org/z3986/2005/ncx-2005-1.dtd\">\n" \
              "<ncx xmlns=\"http://www.daisy.org/z3986/2005/ncx/\" version=\"2005-1\">\n" \
              "<head>\n" \
              "<meta content=\"{0}\" name=\"dtb:uid\"/>\n" \
              "<meta content=\"{1}\" name=\"dtb:depth\"/>\n" \
              "<meta content=\"0\" name=\"dtb:totalPageCount\"/>\n" \
              "<meta content=\"0\" name=\"dtb:maxPageNumber\"/>\n" \
              "</head>\n" \
              "<docTitle><text>{2}</text></docTitle>\n" \
              "<docAuthor><text>{3}</text></docAuthor>\n" \
              "<navMap>{4}</navMap>\n" \
              "</ncx>"

    HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": LOGIN_ENTRY_URL,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "sec-ch-ua": '"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/126.0.0.0 Safari/537.36"
    }

    COOKIE_FLOAT_MAX_AGE_PATTERN = re.compile(r'(max-age=\d*\.\d*)', re.IGNORECASE)

    # Valid book ID patterns: ISBN-10, ISBN-13, or O'Reilly internal IDs
    BOOK_ID_PATTERN = re.compile(r'^[0-9]{10,13}$')

    @property
    def debug(self) -> bool:
        """Check if debug mode is enabled."""
        return getattr(self.args, 'debug', False)

    def __init__(self, args):
        self.args = args
        self.display = Display("info_%s.log" % escape(args.bookid))
        self.display.intro()

        # Security: Validate book ID format to prevent injection
        self.book_id = args.bookid
        if not self.BOOK_ID_PATTERN.match(self.book_id):
            self.display.exit(f"Invalid book ID format: '{self.book_id}'\n"
                              "    Book ID must be 10-13 digits (ISBN-10, ISBN-13, or O'Reilly ID).")

        # Initialize diagnostic collector (enabled with --debug flag)
        self.diagnostics = DiagnosticCollector(
            enabled=getattr(args, 'debug', False),
            book_id=self.book_id
        )

        # Initialize filename mapping (populated by build_filename_mapping)
        self.filename_mapping = {}
        self.content_url_to_filename = {}

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        if USE_PROXY:  # DEBUG
            self.session.proxies = PROXIES
            self.session.verify = False

        self.session.headers.update(self.HEADERS)

        self.jwt = {}

        # Show deprecation warning for --cred/--login (but don't block)
        if args.cred:
            self.display.out("\n[!] Note: --cred and --login are deprecated (O'Reilly API changed).")
            self.display.out("    Will use browser-based authentication instead.\n")

        # O'Reilly's content API sits behind Akamai Bot Manager, which serves
        # "403 AkamaiGHost" to non-browser HTTP clients (plain requests) even
        # with a valid cookie jar. The only client that passes is a real,
        # logged-in Chrome, so route all content requests through one via CDP.
        # Saved cookies (if any) are injected so login is usually automatic.
        self.browser = BrowserTransport(COOKIES_FILE, self.display)
        try:
            self.browser.start()
        except KeyboardInterrupt:
            self.browser.close()
            self.display.exit("Login cancelled.")
        except Exception as e:
            self.browser.close()
            self.display.exit(f"Browser startup failed: {e}")

        self.check_login()

        self.book_id = args.bookid
        self.api_url = self.API_V2_EPUBS.format(self.book_id)

        self.display.info("Retrieving book info...")
        self.book_info = self.get_book_info()
        self.display.book_info(self.book_info)

        self.display.info("Retrieving book chapters...")
        self.book_chapters = self.fix_duplicate_filenames(self.get_book_chapters())
        self.build_filename_mapping()

        self.chapters_queue = deque(self.book_chapters)

        if len(self.book_chapters) > sys.getrecursionlimit():
            sys.setrecursionlimit(len(self.book_chapters))

        self.book_title = self.book_info["title"]
        self.base_url = self.book_info["web_url"]

        # Generate EPUB filename from title and author
        self.epub_filename = self.generate_epub_filename(
            self.book_title,
            self.book_info.get("authors", [])
        )

        self.clean_book_title = "".join(self.escape_dirname(self.book_title).split(",")[:2]) \
                                + " ({0})".format(self.book_id)

        books_dir = os.path.join(PATH, "Books")
        if not os.path.isdir(books_dir):
            os.mkdir(books_dir)

        self.BOOK_PATH = os.path.join(books_dir, self.clean_book_title)
        self.display.set_output_dir(self.BOOK_PATH)
        self.css_path = ""
        self.images_path = ""
        self.create_dirs()

        self.chapter_title = ""
        self.filename = ""
        self.chapter_stylesheets = []
        self.css = []
        self._css_index = {}
        self.images = []
        self._image_urls = set()
        self._image_basenames = set()
        self.css_asset_paths = []  # Fonts and images referenced in CSS

        self.display.info("Downloading book contents... (%s chapters)" % len(self.book_chapters), state=True)
        # Include Kindle-friendly CSS rules WHEN --kindle flag is passed
        self.BASE_HTML = self.BASE_01_HTML + (self.KINDLE_HTML if args.kindle else "") + self.BASE_02_HTML

        self.cover = False
        self.get()
        if not self.cover:
            self.cover = self.get_default_cover() if "cover" in self.book_info else False

        if self.cover:
            cover_html = self.parse_html(
                html.fromstring("<div id=\"sbo-rt-content\"><img src=\"Images/{0}\"></div>".format(self.cover)), True
            )

            self.book_chapters = [{
                "filename": "default_cover.xhtml",
                "title": "Cover"
            }] + self.book_chapters

            self.filename = self.book_chapters[0]["filename"]
            self.save_page_html(cover_html)

        self.css_done_queue = Queue(0) if sys.platform != "win32" else WinQueue()
        self.display.info("Downloading book CSSs... (%s files)" % len(self.css), state=True)
        self.collect_css()
        self.collect_css_assets()  # Download fonts/images referenced in CSS
        self.images_done_queue = Queue(0) if sys.platform != "win32" else WinQueue()
        self.display.info("Downloading book images... (%s files)" % len(self.images), state=True)
        self.collect_images()

        self.display.info("Creating EPUB file...", state=True)
        self.create_epub()

        if not args.no_cookies:
            saved = self.browser.save_cookies(COOKIES_FILE)
            if saved:
                self.display.info(f"Saved {saved} session cookies for next run.", state=True)

        # Network work is done; release the browser session.
        self.browser.close()

        # Diagnostic finalization (only when --debug enabled)
        if self.diagnostics.enabled:
            epub_path = os.path.join(self.BOOK_PATH, self.epub_filename)
            self.diagnostics.validate_epub(epub_path)
            report_path = os.path.join(self.BOOK_PATH, f"diagnostic_report_{self.book_id}.json")
            self.diagnostics.save_report(report_path)
            self.display.out(self.diagnostics.print_summary())

        self.display.done(os.path.join(self.BOOK_PATH, self.epub_filename))

        # Run EPUB conversion if requested
        if getattr(args, 'convert', False):
            epub_path = os.path.join(self.BOOK_PATH, self.epub_filename)
            self.run_conversion(epub_path)

        # Render to PDF if requested (for books with positioned layouts)
        if getattr(args, 'pdf', False):
            self.run_pdf_render()
        else:
            # Auto-detect converted PDFs and recommend --pdf
            from pdf_renderer import is_converted_pdf
            oebps_dir = os.path.join(self.BOOK_PATH, "OEBPS")
            if is_converted_pdf(oebps_dir):
                self.display.warn(
                    "This book uses fixed-layout positioning (converted PDF).\n"
                    "    EPUB will not render faithfully. Re-run with --pdf for proper output.\n"
                    "    Requires: pip install playwright pypdf && playwright install chromium"
                )

        self.display.unregister()

        if not self.display.in_error and not args.log:
            os.remove(self.display.log_file)

    def handle_cookie_update(self, set_cookie_headers):
        for morsel in set_cookie_headers:
            # Handle Float 'max-age' Cookie
            if self.COOKIE_FLOAT_MAX_AGE_PATTERN.search(morsel):
                cookie_key, cookie_value = morsel.split(";")[0].split("=")
                self.session.cookies.set(cookie_key, cookie_value)

    def requests_provider(self, url, is_post=False, data=None, perform_redirect=True, timeout=REQUESTS_TIMEOUT, **kwargs):
        # Route GETs through the logged-in browser (Akamai blocks plain requests
        # on content endpoints). fetch() follows redirects itself, so there is no
        # redirect recursion here. POSTs (legacy login) fall through to requests.
        browser = getattr(self, "browser", None)
        if browser is not None and browser.active and not is_post:
            response = browser.fetch(url, timeout=timeout)
            if response is None:
                return 0
            self.display.last_request = (
                url, data, kwargs, response.status_code,
                "\n".join("\t{}: {}".format(k, v) for k, v in response.headers.items()),
                response.text,
            )
            return response

        try:
            response = getattr(self.session, "post" if is_post else "get")(
                url,
                data=data,
                allow_redirects=False,
                timeout=timeout,
                **kwargs
            )

            self.handle_cookie_update(response.raw.headers.getlist("Set-Cookie"))

            self.display.last_request = (
                url, data, kwargs, response.status_code, "\n".join(
                    ["\t{}: {}".format(*h) for h in response.headers.items()]
                ), response.text
            )

        except (requests.ConnectionError, requests.ConnectTimeout, requests.RequestException) as request_exception:
            self.display.error(str(request_exception))
            return 0

        if response.is_redirect and perform_redirect:
            return self.requests_provider(response.next.url, is_post, None, perform_redirect)
            # TODO How about **kwargs?

        return response

    def safe_json_response(self, response, context="API"):
        """Safely parse JSON from a response, with helpful error messages on failure."""
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError):
            status = response.status_code
            body_preview = response.text[:500] if response.text else "(empty response)"
            self.display.error(
                f"{context}: HTTP {status} - expected JSON but got:\n    {body_preview}"
            )
            if status == 403:
                self.display.exit(
                    f"{context}: Access forbidden (HTTP 403). Your cookies may be expired "
                    "or your subscription may not include this content.\n"
                    "    Try refreshing cookies: python3 sso_cookies.py \"<cookie_string>\""
                )
            elif status == 401:
                self.display.exit(
                    f"{context}: Authentication failed (HTTP 401). Your session has expired.\n"
                    "    Try refreshing cookies: python3 sso_cookies.py \"<cookie_string>\""
                )
            elif status == 404:
                self.display.exit(
                    f"{context}: Not found (HTTP 404). Check that the book ID is correct."
                )
            else:
                self.display.exit(
                    f"{context}: Unexpected response (HTTP {status}). "
                    "The API may have changed or your session may be invalid.\n"
                    "    Try refreshing cookies: python3 sso_cookies.py \"<cookie_string>\""
                )

    @staticmethod
    def _extract_filename_from_reference_id(ref_id):
        """Extract filename from v2 reference_id like '9781633437333-/Text/preface.html'."""
        if not ref_id:
            return "unknown.html"
        # Split on '/' and take the last component
        return ref_id.split("/")[-1] or "unknown.html"

    @staticmethod
    def _extract_href_from_reference_id(ref_id):
        """Extract path from v2 reference_id for TOC href mapping.
        '9781633437333-/Text/preface.html' -> 'Text/preface.html'
        """
        if not ref_id:
            return ""
        if "-/" in ref_id:
            return ref_id.split("-/", 1)[1]
        return ref_id.split("/")[-1]

    def _reshape_toc_v2_to_v1(self, entries):
        """Recursively transform v2 TOC entries to v1 format for parse_toc()."""
        result = []
        for entry in entries:
            ref_id = entry.get("reference_id", "")
            href = self._extract_href_from_reference_id(ref_id)
            v1_entry = {
                "depth": entry.get("depth", 1),
                "href": href,
                "fragment": entry.get("fragment", ""),
                "id": ref_id.replace("/", "_").replace("-", "_") if ref_id else "",
                "label": entry.get("title", ""),
                "children": self._reshape_toc_v2_to_v1(entry.get("children", [])),
            }
            result.append(v1_entry)
        return result

    @staticmethod
    def parse_cred(cred):
        if ":" not in cred:
            return False

        sep = cred.index(":")
        new_cred = ["", ""]
        new_cred[0] = cred[:sep].strip("'").strip('"')
        if "@" not in new_cred[0]:
            return False

        new_cred[1] = cred[sep + 1:]
        return new_cred

    def do_login(self, email, password):
        response = self.requests_provider(self.LOGIN_ENTRY_URL)
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

        next_parameter = None
        try:
            next_parameter = parse_qs(urlparse(response.request.url).query)["next"][0]

        except (AttributeError, ValueError, IndexError):
            self.display.exit("Login: unable to complete login on Safari Books Online. Try again...")

        redirect_uri = API_ORIGIN_URL + quote_plus(next_parameter)

        response = self.requests_provider(
            self.LOGIN_URL,
            is_post=True,
            json={
                "email": email,
                "password": password,
                "redirect_uri": redirect_uri
            },
            perform_redirect=False
        )

        if response == 0:
            self.display.exit("Login: unable to perform auth to Safari Books Online.\n    Try again...")

        if response.status_code != 200:  # TODO To be reviewed
            try:
                error_page = html.fromstring(response.text)
                errors_message = error_page.xpath("//ul[@class='errorlist']//li/text()")
                recaptcha = error_page.xpath("//div[@class='g-recaptcha']")
                messages = (["    `%s`" % error for error in errors_message
                             if "password" in error or "email" in error] if len(errors_message) else []) + \
                           (["    `ReCaptcha required (wait or do logout from the website).`"] if len(
                               recaptcha) else [])
                self.display.exit(
                    "Login: unable to perform auth login to Safari Books Online.\n" + self.display.SH_YELLOW +
                    "[*]" + self.display.SH_DEFAULT + " Details:\n" + "%s" % "\n".join(
                        messages if len(messages) else ["    Unexpected error!"])
                )
            except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                self.display.error(parsing_error)
                self.display.exit(
                    "Login: your login went wrong and it encountered in an error"
                    " trying to parse the login details of Safari Books Online. Try again..."
                )

        self.jwt = response.json()  # TODO: save JWT Tokens and use the refresh_token to restore user session
        response = self.requests_provider(self.jwt["redirect_uri"])
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

    def check_login(self):
        # Use v2 search API to verify authentication (profile URL redirects
        # due to Referer header set in session)
        test_url = self.API_V2_SEARCH.format(self.book_id)
        response = self.requests_provider(test_url, perform_redirect=False)

        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

        elif response.status_code != 200:
            self.display.exit("Authentication issue: unable to verify session (HTTP %s)." % response.status_code)

        self.display.info("Successfully authenticated.", state=True)

    def validate_session(self) -> tuple:
        """
        Test if stored cookies are still valid by making a test API request.
        Uses v2 search API as a lightweight session check (profile URL redirects
        due to Referer header).

        Returns:
            Tuple of (is_valid: bool, error_message: str)
        """
        try:
            # Use v2 search API as session check (lightweight, JSON response)
            test_url = self.API_V2_SEARCH.format(self.book_id)
            response = self.requests_provider(test_url, perform_redirect=False)

            if response == 0:
                return False, "Connection error"

            if response.status_code == 401:
                return False, "Session expired"

            if response.status_code == 403:
                return False, "Access forbidden"

            if response.status_code != 200:
                return False, f"HTTP {response.status_code}"

            return True, ""

        except requests.Timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, str(e)

    def get_book_info(self):
        # Fetch core metadata from v2 epubs endpoint
        epubs_url = self.API_V2_EPUBS.format(self.book_id)
        response = self.requests_provider(epubs_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book info.")

        epub_data = self.safe_json_response(response, context="API (book info)")
        if not isinstance(epub_data, dict) or "title" not in epub_data:
            self.display.exit(self.display.api_error(epub_data if isinstance(epub_data, dict) else {}))

        # Fetch supplementary metadata from search API (authors, cover, publishers)
        search_url = self.API_V2_SEARCH.format(self.book_id)
        search_response = self.requests_provider(search_url)
        search_data = {}
        if search_response != 0:
            search_json = self.safe_json_response(search_response, context="API (search)")
            if isinstance(search_json, dict) and search_json.get("results"):
                search_data = search_json["results"][0]

        # Build description from v2 descriptions dict
        descriptions = epub_data.get("descriptions", {})
        description = descriptions.get("text/plain", "") or descriptions.get("text/html", "")

        # Reshape to v1 format expected by all downstream code
        result = {
            "title": epub_data.get("title", "n/a"),
            "isbn": epub_data.get("isbn") or epub_data.get("identifier", ""),
            "identifier": epub_data.get("identifier", ""),
            "description": description,
            "issued": epub_data.get("publication_date", ""),
            "authors": [{"name": a} for a in search_data.get("authors", [])],
            "publishers": [{"name": p} for p in search_data.get("publishers", [])],
            "web_url": search_data.get("web_url") or (
                SAFARI_BASE_URL + "/library/view/-/" + self.book_id + "/"
            ),
            "subjects": [],
            "rights": "",
            "language": epub_data.get("language") or "en-US",
        }

        # Only include "cover" key if URL is available (downstream checks key existence)
        cover_url = search_data.get("cover_url", "")
        if cover_url:
            result["cover"] = cover_url

        for key, value in result.items():
            if key == "language":
                continue  # language has its own validated fallback above
            if value is None:
                result[key] = 'n/a'

        return result

    def get_book_chapters(self, offset=0):
        page_num = (offset // 100) + 1
        self.diagnostics.track_pagination(page_num, success=True)

        chapters_url = self.API_V2_CHAPTERS.format(self.book_id, offset)
        response = self.requests_provider(chapters_url)
        if response == 0:
            self.diagnostics.track_pagination(page_num, success=False, error="API request failed")
            self.diagnostics.record_failure(
                "chapters", chapters_url, FailureCategory.NETWORK,
                error_message="Unable to retrieve book chapters"
            )
            self.display.exit("API: unable to retrieve book chapters.")

        response_data = self.safe_json_response(response, context="API (chapters)")

        if not isinstance(response_data, dict) or not response_data.get("results"):
            self.diagnostics.record_failure(
                "chapters", chapters_url, FailureCategory.MISSING_CONTENT,
                error_message="No chapter results in API response"
            )
            self.display.exit("API: unable to retrieve book chapters.")

        if offset == 0:
            self.diagnostics.set_expected("chapters", response_data.get("count", 0))

        total = response_data.get("count", 0)
        if total > sys.getrecursionlimit():
            sys.setrecursionlimit(total)

        asset_base_url = self.API_V2_FILES.format(self.book_id)

        # Reshape each v2 chapter to v1 format
        chapters = []
        for ch in response_data["results"]:
            related = ch.get("related_assets", {})

            filename = self._extract_filename_from_reference_id(
                ch.get("reference_id", "")
            )

            # V2 images are full URLs; strip base to get relative paths
            # so existing get() method's concatenation works correctly
            raw_images = related.get("images", [])
            images = []
            files_prefix = asset_base_url + "/"
            for img_url in raw_images:
                if isinstance(img_url, str) and img_url.startswith(files_prefix):
                    images.append(img_url[len(files_prefix):])
                elif isinstance(img_url, str):
                    images.append(img_url)

            # V2 stylesheets are URL strings; wrap in {"url": str} dicts
            raw_stylesheets = related.get("stylesheets", [])
            stylesheets = [{"url": s} for s in raw_stylesheets if isinstance(s, str)]

            v1_chapter = {
                "title": ch.get("title", ""),
                "filename": filename,
                "content": ch.get("content_url", ""),
                "asset_base_url": asset_base_url,
                "images": images,
                "stylesheets": stylesheets,
                "site_styles": [],
            }
            chapters.append(v1_chapter)

        # Move cover chapters to front (matches original behavior)
        covers = [c for c in chapters if "cover" in c["filename"].lower() or "cover" in c["title"].lower()]
        for c in covers:
            chapters.remove(c)
        result = covers + chapters

        # Recurse if more pages
        if response_data.get("next"):
            next_offset = offset + len(response_data["results"])
            result += self.get_book_chapters(offset=next_offset)

        return result

    def get_default_cover(self):
        response = self.requests_provider(self.book_info["cover"], stream=True)
        if response == 0:
            self.display.error("Error trying to retrieve the cover: %s" % self.book_info["cover"])
            return False

        file_ext = response.headers["Content-Type"].split("/")[-1]
        with open(os.path.join(self.images_path, "default_cover." + file_ext), 'wb') as i:
            for chunk in response.iter_content(1024):
                i.write(chunk)

        return "default_cover." + file_ext

    def get_html(self, url):
        response = self.requests_provider(url)
        if response == 0:
            self.display.error(
                "Crawler: network error retrieving page: %s (%s)\n    From: %s" %
                (self.filename, self.chapter_title, url)
            )
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.NETWORK,
                error_message="Network error", context={"url": url}
            )
            return None

        if response.status_code in (401, 403):
            self.display.exit(
                "Crawler: authentication error (%d) retrieving page: %s (%s)\n    From: %s" %
                (response.status_code, self.filename, self.chapter_title, url)
            )

        if response.status_code != 200:
            self.display.error(
                "Crawler: HTTP %d retrieving page: %s (%s)\n    From: %s" %
                (response.status_code, self.filename, self.chapter_title, url)
            )
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.NETWORK,
                error_message="HTTP %d" % response.status_code, context={"url": url}
            )
            return None

        # Detect truncated preview content from expired JWT
        # V2 API returns 200 with ~2KB preview HTML when orm-jwt expires
        content_length = len(response.text)
        if content_length < 3000 and "sbo-rt-content" not in response.text:
            self.display.error(
                "Crawler: possible expired JWT — truncated content (%d bytes) for: %s (%s)" %
                (content_length, self.filename, self.chapter_title)
            )
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.VALIDATION,
                error_message="Truncated content (%d bytes), possible expired JWT" % content_length,
                content_sample=response.text[:500],
                context={"url": url}
            )
            return None

        root = None
        try:
            root = html.fromstring(response.text, base_url=SAFARI_BASE_URL)

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            self.display.error(
                "Crawler: error parsing page: %s (%s)\n    From: %s\n    %s" %
                (self.filename, self.chapter_title, url, parsing_error)
            )
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.PARSING,
                error_message=str(parsing_error), context={"url": url}
            )
            return None

        return root


    def fix_duplicate_filenames(self, chapters):
        """
        Fix duplicate filenames by deriving unique names from content URLs.
        
        The O'Reilly API sometimes returns 'index.xhtml' for all chapters,
        causing them to overwrite each other. This method extracts unique
        identifiers from the content URL path.
        
        For boxed sets with identical directory structures across books,
        a second pass adds numeric suffixes to remaining duplicates.
        
        Example: .../html/ch1/index.xhtml -> ch1_index.xhtml
        """
        debug = self.debug
        
        # Count filename occurrences
        filename_counts = Counter(c.get("filename", "") for c in chapters)
        
        # Find duplicates (filename appears more than once)
        duplicates = {f for f, count in filename_counts.items() if count > 1}
        
        if not duplicates:
            return chapters  # No duplicates, return as-is
        
        if debug:
            self.display.log(f"Duplicate detection: Found {len(duplicates)} duplicate filename patterns")
            for dup in sorted(duplicates):
                self.display.log(f"  - '{dup}' appears {filename_counts[dup]} times")
        
        # First pass: Fix duplicate filenames using parent directory
        for chapter in chapters:
            filename = chapter.get("filename", "")
            if filename in duplicates:
                content_url = chapter.get("content", "")
                # Extract path components from URL
                # e.g., ".../files/html/ch1/index.xhtml" -> ["html", "ch1", "index.xhtml"]
                if "/files/" in content_url:
                    path_part = content_url.split("/files/")[-1]
                    path_components = [p for p in path_part.split("/") if p]
                    
                    if len(path_components) >= 2:
                        # Use parent directory as prefix: ch1_index.xhtml
                        parent_dir = path_components[-2]
                        base_name = path_components[-1]
                        # Ensure .xhtml extension
                        if not base_name.endswith(".xhtml"):
                            base_name = base_name.replace(".html", ".xhtml")
                            if not base_name.endswith(".xhtml"):
                                base_name += ".xhtml"
                        new_filename = f"{parent_dir}_{base_name}"
                        # Clean up double extensions
                        new_filename = new_filename.replace(".xhtml.xhtml", ".xhtml")
                        chapter["filename"] = new_filename
        
        # Second pass: Check for REMAINING duplicates (common in boxed sets)
        # e.g., 6 books all with xhtml/cover.xhtml -> all became xhtml_cover.xhtml
        filename_counts = Counter(c.get("filename", "") for c in chapters)
        remaining_duplicates = {f for f, count in filename_counts.items() if count > 1}
        
        if remaining_duplicates:
            if debug:
                self.display.log(f"Boxed set detected: {len(remaining_duplicates)} duplicates remain after first pass")
                for dup in sorted(remaining_duplicates):
                    self.display.log(f"  - '{dup}' still appears {filename_counts[dup]} times")
            
            # Add numeric suffix to make them unique
            # Track occurrence count for each duplicate filename
            seen_counts = {}
            for chapter in chapters:
                filename = chapter.get("filename", "")
                if filename in remaining_duplicates:
                    # Get occurrence index for this filename
                    if filename not in seen_counts:
                        seen_counts[filename] = 0
                    else:
                        seen_counts[filename] += 1
                    
                    count = seen_counts[filename]
                    if count > 0:  # Keep first occurrence as-is, suffix subsequent ones
                        # Split off extension to insert suffix
                        if "." in filename:
                            name_part, ext = filename.rsplit(".", 1)
                            new_filename = f"{name_part}_{count}.{ext}"
                        else:
                            new_filename = f"{filename}_{count}"
                        
                        if debug:
                            self.display.log(f"  Renamed: {filename} -> {new_filename}")
                        
                        chapter["filename"] = new_filename
        
        # Final verification
        if debug:
            final_counts = Counter(c.get("filename", "") for c in chapters)
            final_duplicates = {f for f, count in final_counts.items() if count > 1}
            if final_duplicates:
                self.display.log(f"WARNING: {len(final_duplicates)} duplicates still remain after fix!")
            else:
                self.display.log(f"Duplicate fix complete: All {len(chapters)} chapter filenames are unique")
        
        return chapters


    def build_filename_mapping(self):
        """
        Build a mapping from various possible link patterns to actual chapter filenames.
        
        This enables link_replace to correctly rewrite chapter-to-chapter links
        when filenames have been made unique (e.g., index.xhtml -> ch1_index.xhtml).
        
        Maps patterns like:
        - 'index.xhtml' -> 'ch1_index.xhtml'
        - 'html/ch1/index.xhtml' -> 'ch1_index.xhtml'  
        - 'ch1/index.xhtml' -> 'ch1_index.xhtml'
        - 'index.xhtml#anchor' -> 'ch1_index.xhtml#anchor' (handled via base lookup)
        """
        self.filename_mapping = {}
        self.content_url_to_filename = {}
        
        for chapter in self.book_chapters:
            actual_filename = chapter.get("filename", "")
            content_url = chapter.get("content", "")
            
            # Ensure xhtml extension
            if actual_filename.endswith(".html"):
                actual_filename = actual_filename.replace(".html", ".xhtml")
            
            # Map content URL to filename (for TOC lookup)
            if content_url:
                self.content_url_to_filename[content_url] = actual_filename
            
            # Extract path part from content URL
            if "/files/" in content_url:
                path_part = content_url.split("/files/")[-1]
                path_components = [p for p in path_part.split("/") if p]
                
                # Map full path (html/ch1/index.xhtml)
                if path_components:
                    full_path = "/".join(path_components)
                    self.filename_mapping[full_path] = actual_filename
                    self.filename_mapping[full_path.replace(".html", ".xhtml")] = actual_filename
                    
                # Map without first directory (ch1/index.xhtml)
                if len(path_components) >= 2:
                    partial_path = "/".join(path_components[1:])
                    self.filename_mapping[partial_path] = actual_filename
                    self.filename_mapping[partial_path.replace(".html", ".xhtml")] = actual_filename
                    
                # Map just the directory/filename combo (ch1/index.xhtml from end)
                if len(path_components) >= 2:
                    dir_file = path_components[-2] + "/" + path_components[-1]
                    self.filename_mapping[dir_file] = actual_filename
                    self.filename_mapping[dir_file.replace(".html", ".xhtml")] = actual_filename
                    
                # Map just the base filename (index.xhtml) - but only if unique
                # This is a fallback; specific paths should take precedence
                base_name = path_components[-1] if path_components else ""
                if base_name and base_name not in self.filename_mapping:
                    self.filename_mapping[base_name] = actual_filename
                    self.filename_mapping[base_name.replace(".html", ".xhtml")] = actual_filename
            
            # Also map the original API filename if different
            original_filename = chapter.get("original_filename", "")
            if original_filename and original_filename != actual_filename:
                self.filename_mapping[original_filename] = actual_filename
                self.filename_mapping[original_filename.replace(".html", ".xhtml")] = actual_filename
        
        self.display.log(f"Built filename mapping with {len(self.filename_mapping)} entries")

    def _add_image(self, full_url, basename):
        if full_url not in self._image_urls and basename not in self._image_basenames:
            self.images.append(full_url)
            self._image_urls.add(full_url)
            self._image_basenames.add(basename)
            return True
        return False

    def _add_css(self, url):
        if url not in self._css_index:
            self._css_index[url] = len(self.css)
            self.css.append(url)
            self.diagnostics.track_detected_asset("css", url)
            self.display.log("Crawler: found a new CSS at %s" % url)
        return self._css_index[url]

    @staticmethod
    def url_is_absolute(url):
        return bool(urlparse(url).netloc)

    @staticmethod
    def is_image_link(url: str):
        return pathlib.Path(url).suffix[1:].lower() in ["jpg", "jpeg", "png", "gif"]

    def link_replace(self, link):
        if link and not link.startswith("mailto"):
            if not self.url_is_absolute(link):
                # Check if this is actually an image file
                # Note: "cover" keyword alone is not enough - must also be an image extension
                # to avoid treating chapter links like "cover.xhtml" as images
                link_lower = link.lower()
                is_image_by_extension = self.is_image_link(link)
                is_in_image_directory = any(x in link_lower for x in ["images/", "graphics/"])
                is_cover_image = "cover" in link_lower and is_image_by_extension
                
                if is_image_by_extension or is_in_image_directory or is_cover_image:
                    image = link.split("/")[-1]
                    
                    # Debug logging for image detection
                    if self.debug:
                        detection_reason = []
                        if is_image_by_extension:
                            detection_reason.append("image_extension")
                        if is_in_image_directory:
                            detection_reason.append("image_directory")
                        if is_cover_image:
                            detection_reason.append("cover_image")
                        self.display.log(f"Image detected: {link} -> Images/{image} (reason: {', '.join(detection_reason)})")
                    
                    # Track detected image for cross-reference validation
                    self.diagnostics.track_detected_asset("images", image)
                    
                    # Add to download queue if not already present
                    # Construct full URL using current chapter's asset base
                    if hasattr(self, 'current_asset_base_url'):
                        if self.current_api_v2_detected:
                            full_url = self.current_asset_base_url + '/' + link.lstrip('/')
                        else:
                            full_url = urljoin(self.current_asset_base_url, link)
                        
                        # Avoid duplicates
                        if self._add_image(full_url, image):
                            self.display.log("Crawler: found additional image: %s" % image)
                    
                    return "Images/" + image
                
                # Debug: Log links that contain "cover" but are NOT treated as images
                if "cover" in link_lower and not is_image_by_extension:
                    if self.debug:
                        self.display.log(f"Link contains 'cover' but not an image (skipped): {link}")

                # Handle chapter-to-chapter links using filename mapping
                # Separate any anchor from the path
                anchor = ""
                link_path = link
                if "#" in link:
                    link_path, anchor = link.split("#", 1)
                    anchor = "#" + anchor
                
                # Normalize the path for lookup
                link_path = link_path.replace(".html", ".xhtml")
                
                # Try to find in filename mapping
                if hasattr(self, 'filename_mapping'):
                    # Try the full path first
                    if link_path in self.filename_mapping:
                        return self.filename_mapping[link_path] + anchor
                    
                    # Try without leading ../
                    clean_path = link_path.lstrip("./")
                    while clean_path.startswith("../"):
                        clean_path = clean_path[3:]
                    
                    if clean_path in self.filename_mapping:
                        return self.filename_mapping[clean_path] + anchor
                    
                    # Try just the filename part
                    basename = link_path.split("/")[-1]
                    if basename in self.filename_mapping:
                        return self.filename_mapping[basename] + anchor
                
                # Fallback: simple extension replacement
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
        if len(root.xpath("//div[@class='controls']/a/text()")):
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.VALIDATION,
                error_message="Rate limit or paywall detected (controls div found)"
            )
            self.display.exit(self.display.api_error(" "))

        book_content = root.xpath("//div[@id='sbo-rt-content']")
        if not len(book_content):
            # Log HTML sample for debugging missing content
            html_sample = html.tostring(root, encoding='unicode')[:1000] if root is not None else "None"
            self.diagnostics.record_failure(
                "chapters", self.filename, FailureCategory.MISSING_CONTENT,
                error_message="Book content div (sbo-rt-content) not found",
                content_sample=html_sample,
                context={"chapter_title": self.chapter_title}
            )
            self.display.error(
                "Parser: book content's corrupted or not present: %s (%s)" %
                (self.filename, self.chapter_title)
            )
            return None

        page_css = ""
        if len(self.chapter_stylesheets):
            for chapter_css_url in self.chapter_stylesheets:
                css_idx = self._add_css(chapter_css_url)
                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(css_idx)

        stylesheet_links = root.xpath("//link[@rel='stylesheet']")
        if len(stylesheet_links):
            for s in stylesheet_links:
                css_url = urljoin("https:", s.attrib["href"]) if s.attrib["href"][:2] == "//" \
                    else urljoin(self.base_url, s.attrib["href"])

                css_idx = self._add_css(css_url)
                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(css_idx)

        stylesheets = root.xpath("//style")
        if len(stylesheets):
            for css in stylesheets:
                if "data-template" in css.attrib and len(css.attrib["data-template"]):
                    css.text = css.attrib["data-template"]
                    del css.attrib["data-template"]

                try:
                    css_str = html.tostring(css, method="xml", encoding='unicode')
                    if isinstance(css_str, (bytes, bytearray, memoryview)):
                        css_str = css_str.tobytes().decode('utf-8') if isinstance(css_str, memoryview) else css_str.decode('utf-8')
                    page_css += css_str + "\n"

                except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                    self.display.error(parsing_error)
                    self.display.exit(
                        "Parser: error trying to parse one CSS found in this page: %s (%s)" %
                        (self.filename, self.chapter_title)
                    )

        # TODO: add all not covered tag for `link_replace` function
        svg_image_tags = root.xpath("//image")
        if len(svg_image_tags):
            for img in svg_image_tags:
                image_attr_href = [x for x in img.attrib.keys() if "href" in x]
                if len(image_attr_href):
                    svg_url = img.attrib.get(image_attr_href[0])
                    # Track SVG image conversion for diagnostics
                    self.diagnostics.track_detected_asset("images", svg_url.split("/")[-1] if "/" in svg_url else svg_url)
                    svg_root = img.getparent().getparent()
                    new_img = svg_root.makeelement("img")
                    new_img.attrib.update({"src": svg_url})
                    svg_root.remove(img.getparent())
                    svg_root.append(new_img)
                else:
                    # SVG image without href - track as skipped
                    self.diagnostics.record_skipped(
                        "images", "unknown_svg", "SVG image element without href attribute"
                    )

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
            self.display.error(parsing_error)
            self.display.exit(
                "Parser: error trying to parse HTML of this page: %s (%s)" %
                (self.filename, self.chapter_title)
            )

        return page_css, xhtml

    @staticmethod
    def escape_dirname(dirname, clean_space=False):
        if ":" in dirname:
            if dirname.index(":") > 15:
                dirname = dirname.split(":")[0]

            elif sys.platform == "win32":
                dirname = dirname.replace(":", ",")

        for ch in ['~', '#', '%', '&', '*', '{', '}', '\\', '<', '>', '?', '/', '`', '\'', '"', '|', '+', ':']:
            if ch in dirname:
                dirname = dirname.replace(ch, "_")

        return dirname if not clean_space else dirname.replace(" ", "")


    @staticmethod
    def generate_epub_filename(title, authors, max_length=200):
        """
        Generate a safe EPUB filename from title and author(s).
        
        Format: <title>_<author>.epub
        
        Args:
            title: Book title string
            authors: List of author dicts with 'name' key, or string
            max_length: Maximum filename length (default 200, safe for most filesystems)
        
        Returns:
            Safe filename string like "Core Java for the Impatient_Cay S. Horstmann.epub"
        """
        # Get first author name
        if isinstance(authors, list) and authors:
            author_name = authors[0].get("name", "Unknown") if isinstance(authors[0], dict) else str(authors[0])
        elif isinstance(authors, str):
            author_name = authors
        else:
            author_name = "Unknown"
        
        # Clean title and author - remove/replace unsafe characters
        # Allowed: letters, numbers, spaces, hyphens, underscores, periods, commas, parentheses
        unsafe_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0', '\n', '\r', '\t']
        
        clean_title = title
        clean_author = author_name
        
        for ch in unsafe_chars:
            clean_title = clean_title.replace(ch, '_')
            clean_author = clean_author.replace(ch, '_')
        
        # Additional cleanup
        # Remove leading/trailing spaces and dots (Windows doesn't like trailing dots)
        clean_title = clean_title.strip(' .')
        clean_author = clean_author.strip(' .')
        
        # Replace multiple consecutive underscores/spaces with single
        clean_title = re.sub(r'[_\s]+', ' ', clean_title).strip()
        clean_author = re.sub(r'[_\s]+', ' ', clean_author).strip()
        
        # Create filename
        base_filename = f"{clean_title}_{clean_author}"
        
        # Truncate if needed (leave room for .epub extension)
        if len(base_filename) > max_length - 5:
            base_filename = base_filename[:max_length - 5].strip(' ._')
        
        return base_filename + ".epub"

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
        open(os.path.join(self.BOOK_PATH, "OEBPS", self.filename), "wb") \
            .write(self.BASE_HTML.format(contents[0], contents[1]).encode("utf-8", 'xmlcharrefreplace'))
        self.display.log("Created: %s" % self.filename)

    def get(self):
        len_books = len(self.book_chapters)

        for _ in range(len_books):
            if not len(self.chapters_queue):
                return

            first_page = len_books == len(self.chapters_queue)

            next_chapter = self.chapters_queue.popleft()
            # Track raw chapter metadata for debugging
            self.diagnostics.track_chapter_metadata(next_chapter)
            self.chapter_title = next_chapter["title"]
            self.filename = next_chapter["filename"]

            asset_base_url = next_chapter['asset_base_url']
            api_v2_detected = False
            if 'v2' in next_chapter['content']:
                asset_base_url = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{}/files".format(self.book_id)
                api_v2_detected = True

            # Store for use by link_replace() during HTML parsing
            self.current_asset_base_url = asset_base_url
            self.current_api_v2_detected = api_v2_detected

            if "images" in next_chapter and len(next_chapter["images"]):
                for img_url in next_chapter['images']:
                    if api_v2_detected:
                        full_url = asset_base_url + '/' + img_url
                    else:
                        full_url = urljoin(next_chapter['asset_base_url'], img_url)
                    self._add_image(full_url, img_url.split('/')[-1])


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
                    self.display.book_ad_info = True
                # Record success for cached chapter
                self.diagnostics.record_success("chapters", self.filename, {"cached": True})

            else:
                page_root = self.get_html(next_chapter["content"])
                if page_root is not None:
                    page_html = self.parse_html(page_root, first_page)
                    if page_html is not None:
                        self.save_page_html(page_html)
                        # Record success for downloaded chapter
                        self.diagnostics.record_success("chapters", self.filename, {"cached": False})
                    else:
                        self.display.error("Skipping chapter: %s (%s)" % (self.filename, self.chapter_title))
                else:
                    self.display.error("Skipping chapter: %s (%s)" % (self.filename, self.chapter_title))

            self.display.state(len_books, len_books - len(self.chapters_queue))

    def _thread_download_css(self, url):
        """Download a single CSS file with proper error handling."""
        css_file = os.path.join(self.css_path, "Style{0:0>2}.css".format(self._css_index[url]))
        try:
            if os.path.isfile(css_file):
                if not self.display.css_ad_info.value:
                    self.display.info(("File `%s` already exists.\n"
                                       "    If you want to download again all the CSSs,\n"
                                       "    please delete the output directory '" + self.BOOK_PATH + "'"
                                       " and restart the program.") %
                                      css_file)
                    self.display.css_ad_info.value = 1
                # Record success for cached file
                self.diagnostics.record_success("css", url, {"cached": True})

            else:
                response = self.requests_provider(url, stream=True)
                if response == 0:
                    # Record failure with context
                    self.diagnostics.record_failure(
                        "css", url, FailureCategory.NETWORK,
                        error_message=f"Error retrieving CSS: {css_file}"
                    )
                    self.display.error("Error trying to retrieve this CSS: %s\n    From: %s" % (css_file, url))
                    return  # Exit but finally block will update queue

                with open(css_file, 'wb') as s:
                    for chunk in response.iter_content(1024):
                        s.write(chunk)
                # Record success for downloaded file
                self.diagnostics.record_success("css", url)

        except Exception as e:
            self.diagnostics.record_failure(
                "css", url, FailureCategory.NETWORK,
                error_message=f"Unexpected error downloading CSS: {e}"
            )
            self.display.error(f"Error downloading CSS {css_file}: {e}")
        finally:
            # Always update queue to prevent deadlocks
            self.css_done_queue.put(1)
            self.display.state(len(self.css), self.css_done_queue.qsize())


    def _thread_download_images(self, url):
        """Download a single image file with proper error handling."""
        image_name = url.split("/")[-1]
        image_path = os.path.join(self.images_path, image_name)
        try:
            if os.path.isfile(image_path):
                if not self.display.images_ad_info.value:
                    self.display.info(("File `%s` already exists.\n"
                                       "    If you want to download again all the images,\n"
                                       "    please delete the output directory '" + self.BOOK_PATH + "'"
                                       " and restart the program.") %
                                      image_name)
                    self.display.images_ad_info.value = 1
                # Record success for cached file
                self.diagnostics.record_success("images", url, {"cached": True})

            else:
                response = self.requests_provider(urljoin(SAFARI_BASE_URL, url), stream=True)
                if response == 0:
                    # Record failure with context
                    self.diagnostics.record_failure(
                        "images", url, FailureCategory.NETWORK,
                        error_message=f"Error retrieving image: {image_name}"
                    )
                    self.display.error("Error trying to retrieve this image: %s\n    From: %s" % (image_name, url))
                    return  # Exit but finally block will update queue

                with open(image_path, 'wb') as img:
                    for chunk in response.iter_content(1024):
                        img.write(chunk)
                # Record success for downloaded file
                self.diagnostics.record_success("images", url)

        except Exception as e:
            self.diagnostics.record_failure(
                "images", url, FailureCategory.NETWORK,
                error_message=f"Unexpected error downloading image: {e}"
            )
            self.display.error(f"Error downloading image {image_name}: {e}")
        finally:
            # Always update queue to prevent deadlocks
            self.images_done_queue.put(1)
            self.display.state(len(self.images), self.images_done_queue.qsize())

    def collect_css(self):
        self.display.state_status.value = -1

        # Set expected CSS count for diagnostics
        self.diagnostics.set_expected("css", len(self.css))

        # Sequential download to avoid rate limiting detection
        for css_url in self.css:
            self._thread_download_css(css_url)

    def parse_css_for_assets(self):
        """
        Parse downloaded CSS files for url() references to fonts and images.
        Returns a dict mapping relative paths (e.g., 'fonts/DejaVu.ttf') to full URLs.

        Security: Uses length-limited regex to prevent catastrophic backtracking.
        """
        css_assets = {}

        # Pattern to match url() references in CSS
        # Matches: url(path), url('path'), url("path")
        # Security: Limit match length to 500 chars to prevent ReDoS attacks
        url_pattern = re.compile(r'url\([\'"]?([^\'")\s]{1,500}?)[\'"]?\)', re.IGNORECASE)

        for css_file in os.listdir(self.css_path):
            if not css_file.endswith('.css'):
                continue

            css_file_path = os.path.join(self.css_path, css_file)
            try:
                with open(css_file_path, 'r', encoding='utf-8') as f:
                    css_content = f.read()
            except Exception as e:
                self.display.log(f"Error reading CSS file {css_file}: {e}")
                continue

            # Find all url() references
            matches = url_pattern.findall(css_content)
            for match in matches:
                # Skip data URIs, absolute URLs, and already processed
                if match.startswith('data:') or match.startswith('http://') or match.startswith('https://'):
                    continue

                # Clean up the path
                asset_path = match.strip()

                # Skip CSS references (those are handled separately)
                if asset_path.endswith('.css'):
                    continue

                # Track unique asset paths
                if asset_path not in css_assets:
                    css_assets[asset_path] = asset_path

        return css_assets

    def _validate_asset_path(self, asset_path):
        """
        Validate asset path for security (prevent path traversal attacks).
        Handles relative paths like '../Misc/font.woff2' by resolving them
        relative to OEBPS directory.
        
        Returns (is_safe, resolved_path, target_dir) tuple.
        - resolved_path: path relative to OEBPS (e.g., 'Misc/font.woff2')
        - target_dir: full filesystem path to target directory
        """
        oebps_path = os.path.join(self.BOOK_PATH, "OEBPS")
        
        # Resolve path relative to Styles/ directory (where CSS files live)
        # '../Misc/font.woff2' from Styles/ becomes 'Misc/font.woff2' relative to OEBPS
        styles_relative = os.path.join("Styles", asset_path)
        normalized_path = os.path.normpath(styles_relative)
        
        # Security: Ensure resolved path doesn't escape OEBPS
        # After normpath, path should not start with '..' or be absolute
        if normalized_path.startswith('..') or os.path.isabs(normalized_path):
            self.display.log(f"Security: Rejected path escaping OEBPS: {asset_path} -> {normalized_path}")
            return False, None, None
        
        # Compute full target path and verify it's within OEBPS
        full_target_path = os.path.abspath(os.path.join(oebps_path, normalized_path))
        oebps_abs = os.path.abspath(oebps_path)
        
        if not full_target_path.startswith(oebps_abs):
            self.display.log(f"Security: Path escape attempt blocked: {asset_path}")
            return False, None, None
        
        # Extract the directory part (e.g., 'Misc' from 'Misc/font.woff2')
        target_dir = os.path.dirname(full_target_path)
        
        # Debug logging
        if self.debug:
            self.display.log(f"CSS asset path resolved: {asset_path} -> {normalized_path} (dir: {target_dir})")
        
        return True, normalized_path, target_dir

    def _validate_asset_url(self, asset_url):
        """
        Validate asset URL to ensure it stays within allowed O'Reilly domains.
        Returns True if URL is safe, False otherwise.
        """
        try:
            parsed_url = urlparse(asset_url)
            allowed_hosts = [SAFARI_BASE_HOST, ORLY_BASE_HOST, API_ORIGIN_HOST]

            # Check if hostname ends with any allowed host
            if parsed_url.hostname:
                for allowed in allowed_hosts:
                    if parsed_url.hostname == allowed or parsed_url.hostname.endswith('.' + allowed):
                        return True

            self.display.log(f"Security: Blocked external URL: {asset_url}")
            return False
        except Exception as e:
            self.display.log(f"Security: URL validation error: {e}")
            return False

    def download_css_asset(self, asset_path, base_css_url):
        """
        Download a single CSS-referenced asset (font or image).
        asset_path: relative path like 'fonts/DejaVu.ttf' or '../Misc/font.woff2'
        base_css_url: URL of a CSS file to derive the asset URL

        Security: Validates paths and URLs to prevent path traversal and SSRF.
        Uses atomic file writes to prevent corruption on failure.
        
        Returns tuple (success: bool, resolved_path: str or None)
        - resolved_path: path relative to OEBPS (e.g., 'Misc/font.woff2')
        """
        # Security: Validate asset path and resolve relative to OEBPS
        is_safe, resolved_path, target_dir = self._validate_asset_path(asset_path)
        if not is_safe:
            return False, None

        # Determine the target file path
        oebps_path = os.path.join(self.BOOK_PATH, "OEBPS")
        target_path = os.path.join(oebps_path, resolved_path)

        # Create target directory if needed (e.g., OEBPS/Misc/)
        if target_dir and not os.path.isdir(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            if self.debug:
                self.display.log(f"Created directory for CSS asset: {target_dir}")

        # Skip if already exists
        if os.path.isfile(target_path):
            self.display.log(f"CSS asset already exists: {resolved_path}")
            return True, resolved_path

        # Construct the asset URL from the CSS URL base
        if not base_css_url:
            self.display.log(f"No base URL for asset: {asset_path}")
            return False, None

        base_url = base_css_url.rsplit('/', 1)[0] + '/'
        asset_url = urljoin(base_url, asset_path)

        # Security: Validate the constructed URL
        if not self._validate_asset_url(asset_url):
            return False, None

        # Download the asset
        response = self.requests_provider(asset_url, stream=True)
        if response == 0:
            self.display.log(f"Failed to download CSS asset: {asset_path} from {asset_url}")
            return False, None

        # Atomic write: Write to temp file first, then rename on success
        temp_file_path = None
        try:
            # Create temp file in target directory for atomic rename
            fd, temp_file_path = tempfile.mkstemp(dir=target_dir)
            with os.fdopen(fd, 'wb') as f:
                for chunk in response.iter_content(1024):
                    f.write(chunk)

            # Atomic rename on success
            shutil.move(temp_file_path, target_path)
            temp_file_path = None  # Successfully moved, don't delete in finally
            self.display.log(f"Downloaded CSS asset: {resolved_path}")
            return True, resolved_path

        except Exception as e:
            self.display.log(f"Error saving CSS asset {asset_path}: {e}")
            return False, None

        finally:
            # Clean up temp file on failure
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.unlink(temp_file_path)
                except Exception:
                    pass

    def collect_css_assets(self):
        """
        Parse CSS files for url() references and download fonts/images.
        Includes diagnostic tracking for completeness monitoring.
        Assets may be saved to various directories (Styles/, Misc/, etc.)
        """
        if not self.css:
            return

        # Parse CSS files for asset references
        css_assets = self.parse_css_for_assets()

        if not css_assets:
            self.display.log("No CSS assets found to download")
            return

        self.display.info(f"Downloading CSS assets... ({len(css_assets)} files)", state=True)

        # Set expected count for diagnostic tracking
        self.diagnostics.set_expected("css_assets", len(css_assets))

        # Use the first CSS URL as the base for constructing asset URLs
        base_css_url = self.css[0] if self.css else None

        downloaded = 0
        failed = 0
        resolved_paths = []  # Track resolved paths for manifest generation
        
        for asset_path in css_assets:
            success, resolved_path = self.download_css_asset(asset_path, base_css_url)
            if success:
                downloaded += 1
                self.diagnostics.record_success("css_assets", asset_path)
                if resolved_path:
                    resolved_paths.append(resolved_path)
            else:
                failed += 1
                self.diagnostics.record_failure(
                    "css_assets", asset_path, FailureCategory.NETWORK,
                    error_message=f"Failed to download CSS asset: {asset_path}"
                )

        self.display.log(f"CSS assets: {downloaded} downloaded, {failed} failed")

        # Store the resolved paths for manifest generation
        # These are relative to OEBPS (e.g., 'Styles/fonts/x.ttf' or 'Misc/font.woff2')
        self.css_asset_paths = resolved_paths

    def collect_images(self):
        if self.display.book_ad_info == 2:
            self.display.info("Some of the book contents were already downloaded.\n"
                              "    If you want to be sure that all the images will be downloaded,\n"
                              "    please delete the output directory '" + self.BOOK_PATH +
                              "' and restart the program.")

        self.display.state_status.value = -1

        # Set expected image count for diagnostics
        self.diagnostics.set_expected("images", len(self.images))

        # Sequential download to avoid rate limiting detection
        for image_url in self.images:
            self._thread_download_images(image_url)

    def create_content_opf(self):
        # Filter to only include .css files (not fonts/images in Styles directory)
        self.css = [f for f in next(os.walk(self.css_path))[2] if f.endswith('.css')]
        self.images = next(os.walk(self.images_path))[2]

        manifest = []
        spine = []

        # Track chapter manifest entries to detect duplicates (safety check for boxed sets)
        seen_chapter_ids = {}
        seen_chapter_files = {}

        for c in self.book_chapters:
            c["filename"] = c["filename"].replace(".html", ".xhtml")
            item_id = escape("".join(c["filename"].split(".")[:-1]))

            # Check for duplicate manifest IDs (should be fixed by fix_duplicate_filenames)
            if item_id in seen_chapter_ids:
                if self.debug:
                    self.display.log(f"WARNING: Duplicate chapter manifest ID: {item_id} (file: {c['filename']}, previous: {seen_chapter_ids[item_id]})")
                # Skip to avoid invalid EPUB manifest
                continue

            # Check for duplicate filenames
            if c["filename"] in seen_chapter_files:
                if self.debug:
                    self.display.log(f"WARNING: Duplicate chapter filename: {c['filename']} (title: {c.get('title', 'N/A')})")
                continue

            seen_chapter_ids[item_id] = c["filename"]
            seen_chapter_files[c["filename"]] = item_id

            manifest.append("<item id=\"{0}\" href=\"{1}\" media-type=\"application/xhtml+xml\" />".format(
                item_id, c["filename"]
            ))
            spine.append("<itemref idref=\"{0}\"/>".format(item_id))

        # Track manifest IDs to detect duplicates
        seen_image_ids = {}
        for i in set(self.images):
            # Use rsplit to split only on last dot, preserving dots in filename
            # This prevents ID collisions between e.g., "11.9.png" and "119.png"
            parts = i.rsplit(".", 1)
            if len(parts) == 2:
                base_name = parts[0].replace(".", "_")
                extension = parts[1]
                head = "img_" + escape(base_name) + "_" + escape(extension)
            else:
                # No extension (shouldn't happen for valid images)
                extension = ""
                head = "img_" + escape(i)

            # Check for duplicate manifest IDs (shouldn't happen now with extension in ID)
            if head in seen_image_ids:
                if self.debug:
                    self.display.log(f"WARNING: Duplicate image manifest ID: {head} (files: {seen_image_ids[head]}, {i})")
                continue
            seen_image_ids[head] = i

            manifest.append("<item id=\"{0}\" href=\"Images/{1}\" media-type=\"image/{2}\" />".format(
                head, i, "jpeg" if "jp" in extension else extension
            ))

        for i in range(len(self.css)):
            manifest.append("<item id=\"style_{0:0>2}\" href=\"Styles/Style{0:0>2}.css\" "
                            "media-type=\"text/css\" />".format(i))

        # Add CSS-referenced assets (fonts and icons) to manifest
        # asset_path is relative to OEBPS (e.g., 'Styles/fonts/x.ttf' or 'Misc/font.woff2')
        oebps_path = os.path.join(self.BOOK_PATH, "OEBPS")
        for asset_path in getattr(self, 'css_asset_paths', []):
            # Check if the file actually exists
            full_path = os.path.join(oebps_path, asset_path)
            if not os.path.isfile(full_path):
                if self.debug:
                    self.display.log(f"CSS asset not found for manifest: {asset_path}")
                continue

            # Generate unique ID from path
            safe_id = escape(asset_path.replace('/', '_').replace('.', '_'))

            # Determine media type based on extension
            ext = asset_path.split('.')[-1].lower()
            if ext == 'ttf':
                media_type = 'font/ttf'
            elif ext == 'otf':
                media_type = 'font/otf'
            elif ext == 'woff':
                media_type = 'font/woff'
            elif ext == 'woff2':
                media_type = 'font/woff2'
            elif ext == 'eot':
                media_type = 'application/vnd.ms-fontobject'
            elif ext == 'png':
                media_type = 'image/png'
            elif ext in ('jpg', 'jpeg'):
                media_type = 'image/jpeg'
            elif ext == 'gif':
                media_type = 'image/gif'
            elif ext == 'svg':
                media_type = 'image/svg+xml'
            else:
                media_type = 'application/octet-stream'

            # asset_path is already relative to OEBPS, use directly
            manifest.append("<item id=\"{0}\" href=\"{1}\" media-type=\"{2}\" />".format(
                safe_id, asset_path, media_type
            ))

        authors = "\n".join("<dc:creator opf:file-as=\"{0}\" opf:role=\"aut\">{0}</dc:creator>".format(
            escape(aut.get("name", "n/d"))
        ) for aut in self.book_info.get("authors", []))

        subjects = "\n".join("<dc:subject>{0}</dc:subject>".format(escape(sub.get("name", "n/d")))
                             for sub in self.book_info.get("subjects", []))

        # Convert cover path to manifest ID
        # self.cover is like "Images/cover.jpg" or "default_cover.jpg"
        # The manifest ID should be like "img_cover_jpg" (includes extension for uniqueness)
        cover_manifest_id = ""
        if self.cover:
            # Extract just the filename (in case it has Images/ prefix)
            cover_filename = self.cover.split("/")[-1] if "/" in str(self.cover) else str(self.cover)
            # Generate ID same way as image manifest entries: img_ + base name + extension
            cover_parts = cover_filename.split(".")
            cover_base = "".join(cover_parts[:-1])
            cover_ext = cover_parts[-1] if len(cover_parts) > 1 else ""
            cover_manifest_id = "img_" + escape(cover_base) + "_" + escape(cover_ext)

            # Debug logging for cover manifest ID
            if self.debug:
                self.display.log(f"Cover manifest ID: {self.cover} -> {cover_manifest_id}")

        return self.CONTENT_OPF.format(
            (self.book_info.get("isbn",  self.book_id)),
            escape(self.book_title),
            authors,
            escape(self.book_info.get("description", "")),
            subjects,
            ", ".join(escape(pub.get("name", "")) for pub in self.book_info.get("publishers", [])),
            escape(self.book_info.get("rights", "")),
            self.book_info.get("issued", ""),
            '<meta name="cover" content="{0}"/>\n'.format(cover_manifest_id) if cover_manifest_id else "",
            "\n".join(manifest),
            "\n".join(spine),
            self.book_chapters[0]["filename"].replace(".html", ".xhtml"),
            escape(self.book_info.get("language", "en-US"))
        )

    @staticmethod
    def parse_toc(toc_list, filename_mapping=None, c=0, mx=0):
        r = ""
        for cc in toc_list:
            c += 1
            if int(cc["depth"]) > mx:
                mx = int(cc["depth"])

            # Get the href and any anchor
            href = cc["href"].replace(".html", ".xhtml")
            anchor = ""
            if "#" in href:
                href_path, anchor = href.split("#", 1)
                anchor = "#" + anchor
            else:
                href_path = href
            
            # Try to resolve the filename using the mapping
            resolved_filename = href_path.split("/")[-1]  # Default fallback
            
            if filename_mapping:
                # Try various path patterns
                for pattern in [href_path, href_path.lstrip("./"), href_path.split("/")[-1]]:
                    # Also try without leading ../
                    clean_pattern = pattern
                    while clean_pattern.startswith("../"):
                        clean_pattern = clean_pattern[3:]
                    
                    if pattern in filename_mapping:
                        resolved_filename = filename_mapping[pattern]
                        break
                    elif clean_pattern in filename_mapping:
                        resolved_filename = filename_mapping[clean_pattern]
                        break
            
            r += "<navPoint id=\"{0}\" playOrder=\"{1}\">" \
                 "<navLabel><text>{2}</text></navLabel>" \
                 "<content src=\"{3}\"/>".format(
                    cc["fragment"] if len(cc["fragment"]) else cc["id"], c,
                    escape(cc["label"]), resolved_filename + anchor
                 )

            if cc["children"]:
                sr, c, mx = SafariBooks.parse_toc(cc["children"], filename_mapping, c, mx)
                r += sr

            r += "</navPoint>\n"

        return r, c, mx

    def create_toc(self):
        toc_url = self.API_V2_TOC.format(self.book_id)
        response = self.requests_provider(toc_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book TOC. "
                              "Don't delete any files, just run again this program"
                              " in order to complete the `.epub` creation!")

        response_data = self.safe_json_response(response, context="API (TOC)")

        if not isinstance(response_data, list):
            self.display.exit(
                "API: unexpected TOC format. "
                "Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!"
            )

        # Reshape v2 TOC entries to v1 format for parse_toc
        v1_toc = self._reshape_toc_v2_to_v1(response_data)

        navmap, _, max_depth = self.parse_toc(v1_toc, self.filename_mapping)
        return self.TOC_NCX.format(
            (self.book_info["isbn"] if self.book_info["isbn"] else self.book_id),
            max_depth,
            escape(self.book_title),
            escape(", ".join(aut.get("name", "") for aut in self.book_info.get("authors", []))),
            navmap
        )

    def create_epub(self):
        open(os.path.join(self.BOOK_PATH, "mimetype"), "w").write("application/epub+zip")
        meta_info = os.path.join(self.BOOK_PATH, "META-INF")
        if os.path.isdir(meta_info):
            self.display.log("META-INF directory already exists: %s" % meta_info)

        else:
            os.makedirs(meta_info)

        open(os.path.join(meta_info, "container.xml"), "wb").write(
            self.CONTAINER_XML.encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "content.opf"), "wb").write(
            self.create_content_opf().encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "toc.ncx"), "wb").write(
            self.create_toc().encode("utf-8", "xmlcharrefreplace")
        )

        zip_file = os.path.join(PATH, "Books", self.book_id)
        if os.path.isfile(zip_file + ".zip"):
            os.remove(zip_file + ".zip")

        shutil.make_archive(zip_file, 'zip', self.BOOK_PATH)
        os.rename(zip_file + ".zip", os.path.join(self.BOOK_PATH, self.epub_filename))

    def run_conversion(self, epub_path):
        """Run convert-epub.sh to produce a cleaned final.epub via mobi round-trip."""
        script_path = os.path.join(PATH, "scripts", "convert-epub.sh")

        if not os.path.isfile(script_path):
            self.display.out(f"[!] Conversion script not found: {script_path}")
            return False

        self.display.out("\n")  # Newline before conversion output
        try:
            result = subprocess.run(
                [script_path, epub_path],
                timeout=600  # 10 minute timeout for large books
            )
            if result.returncode == 0:
                final_epub = epub_path.replace(".epub", ".final.epub")
                self.display.out(f"[OK] Converted: {final_epub}")
                return True
            else:
                self.display.out(f"[!] Conversion failed (exit code {result.returncode})")
                return False
        except subprocess.TimeoutExpired:
            self.display.out("\n[!] Conversion timed out after 10 minutes")
            return False
        except Exception as e:
            self.display.out(f"\n[!] Conversion error: {e}")
            return False

    def run_pdf_render(self):
        """Render book pages to PDF via headless Chromium.

        Best for scanned/converted books where text is absolutely positioned
        over background images (pdf2htmlEX-style content).
        """
        from pdf_renderer import convert_to_pdf

        oebps_dir = os.path.join(self.BOOK_PATH, "OEBPS")
        pdf_filename = self.epub_filename.replace(".epub", ".pdf")
        output_pdf = os.path.join(self.BOOK_PATH, pdf_filename)

        # Build metadata dict from book info
        authors = self.book_info.get("authors", [])
        if isinstance(authors, list) and authors:
            author_str = ", ".join(
                a.get("name", "") if isinstance(a, dict) else str(a)
                for a in authors
            )
        elif isinstance(authors, str):
            author_str = authors
        else:
            author_str = None

        metadata = {
            "title": self.book_title,
            "author": author_str,
        }

        convert_to_pdf(oebps_dir, output_pdf, display=self.display, metadata=metadata)
