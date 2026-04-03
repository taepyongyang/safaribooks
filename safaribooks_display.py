import logging
import os
import shutil
import sys
import traceback
from multiprocessing import Value
from random import random

from lxml import html

# Import configuration constants
from safaribooks_config import COOKIES_FILE, PATH, SAFARI_BASE_URL

# ANSI color support detection
# BUG FIX: old check "win" not in sys.platform was False on macOS
# because "darwin" contains "win". Use exact platform match instead.
_IS_WIN = sys.platform == "win32"

# Module-level color constants (importable by other modules)
C_RESET = "\033[0m" if not _IS_WIN else ""
C_BOLD = "\033[1m" if not _IS_WIN else ""
C_DIM = "\033[2m" if not _IS_WIN else ""
C_RED = "\033[31m" if not _IS_WIN else ""
C_GREEN = "\033[32m" if not _IS_WIN else ""
C_YELLOW = "\033[33m" if not _IS_WIN else ""
C_BLUE = "\033[34m" if not _IS_WIN else ""
C_MAGENTA = "\033[35m" if not _IS_WIN else ""
C_CYAN = "\033[36m" if not _IS_WIN else ""
C_BG_RED = "\033[41m" if not _IS_WIN else ""
C_BG_YELLOW = "\033[43m" if not _IS_WIN else ""

# Banner color gradient (cycles per line for visual interest)
_BANNER_COLORS = [C_CYAN, C_BLUE, C_MAGENTA, C_CYAN, C_BLUE, C_MAGENTA, C_CYAN]


class Display:
    """
    Handles all user-facing output, logging, and error reporting for the SafariBooks downloader.
    Provides methods for info, error, progress, and formatted console output.
    """
    BASE_FORMAT = logging.Formatter(
        fmt="[%(asctime)s] %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S"
    )

    # Backward-compatible class-level aliases
    SH_DEFAULT = C_RESET
    SH_YELLOW = C_YELLOW
    SH_BG_RED = C_BG_RED
    SH_BG_YELLOW = C_BG_YELLOW

    def __init__(self, log_file):
        self.output_dir = ""
        self.output_dir_set = False
        self.log_file = os.path.join(PATH, log_file)

        self.logger = logging.getLogger("SafariBooks")
        self.logger.setLevel(logging.INFO)
        logs_handler = logging.FileHandler(filename=self.log_file)
        logs_handler.setFormatter(self.BASE_FORMAT)
        logs_handler.setLevel(logging.INFO)
        self.logger.addHandler(logs_handler)

        self.columns, _ = shutil.get_terminal_size()

        self.logger.info("** Welcome to SafariBooks! **")

        self.book_ad_info = False
        self.css_ad_info = Value("i", 0)
        self.images_ad_info = Value("i", 0)
        self.last_request: tuple[str, str | None, dict, int, str, str] = ("", None, {}, 0, "", "")
        self.in_error = False

        self.state_status = Value("i", 0)
        sys.excepthook = self.unhandled_exception

    def set_output_dir(self, output_dir):
        self.info("Output directory:\n    %s" % output_dir)
        self.output_dir = output_dir
        self.output_dir_set = True

    def unregister(self):
        self.logger.handlers[0].close()
        sys.excepthook = sys.__excepthook__

    def log(self, message):
        try:
            self.logger.info(str(message, "utf-8", "replace"))
        except (UnicodeDecodeError, Exception):
            self.logger.info(message)

    def out(self, put):
        pattern = "\r{!s}\r{!s}\n"
        try:
            s = pattern.format(" " * self.columns, str(put, "utf-8", "replace"))
        except TypeError:
            s = pattern.format(" " * self.columns, put)
        sys.stdout.write(s)

    def info(self, message, state=False):
        self.log(message)
        if state:
            output = (f"\n{C_DIM}{'━' * 40}{C_RESET}\n"
                      f" {C_BOLD}{C_CYAN}▶{C_RESET}  {C_BOLD}{message}{C_RESET}")
        else:
            output = f" {C_CYAN}›{C_RESET}  {message}"
        self.out(output)

    def error(self, error):
        if not self.in_error:
            self.in_error = True
        self.log(error)
        output = f" {C_RED}✗{C_RESET}  {error}"
        self.out(output)

    def warn(self, message):
        self.log(message)
        output = f" {C_YELLOW}⚠{C_RESET}  {message}"
        self.out(output)

    def success(self, message):
        self.log(message)
        output = f" {C_GREEN}✓{C_RESET}  {message}"
        self.out(output)

    def exit(self, error):
        self.error(str(error))
        if self.output_dir_set:
            output = (f" {C_YELLOW}›{C_RESET}  Please delete the output directory "
                      f"'{self.output_dir}' and restart the program.")
            self.out(output)
        output = f"\n {C_BG_RED}{C_BOLD} ABORT {C_RESET}  Shutting down...\n"
        self.out(output)
        self.save_last_request()
        sys.exit(1)

    def unhandled_exception(self, _, o, tb):
        self.log("".join(traceback.format_tb(tb)))
        self.exit("Unhandled Exception: %s (type: %s)" % (o, o.__class__.__name__))

    def save_last_request(self):
        if any(self.last_request):
            self.log("Last request done:\n\tURL: {0}\n\tDATA: {1}\n\tOTHERS: {2}\n\n\t{3}\n{4}\n\n{5}\n"
                     .format(*self.last_request))

    def intro(self):
        banner = (r"""
     ____     ___         _
    / __/__ _/ _/__ _____(_)
   _\ \/ _ `/ _/ _ `/ __/ /
  /___/\_,_/_/ \_,_/_/ /_/
    / _ )___  ___  / /__ ___
   / _  / _ \/ _ \/  '_/(_-<
  /____/\___/\___/_/\_\/___/
""" if random() > 0.5 else r"""
 ██████╗     ██████╗ ██╗  ██╗   ██╗██████╗
██╔═══██╗    ██╔══██╗██║  ╚██╗ ██╔╝╚════██╗
██║   ██║    ██████╔╝██║   ╚████╔╝   ▄███╔╝
██║   ██║    ██╔══██╗██║    ╚██╔╝    ▀▀══╝
╚██████╔╝    ██║  ██║███████╗██║     ██╗
 ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
""")
        # Color gradient across banner lines
        lines = banner.strip('\n').split('\n')
        colored = '\n'.join(
            _BANNER_COLORS[i % len(_BANNER_COLORS)] + C_BOLD + line
            for i, line in enumerate(lines)
        )
        output = colored + C_RESET
        output += "\n" + C_DIM + "━" * (self.columns // 2) + C_RESET
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
        self.out(f"\n{C_DIM}{'─' * 40}{C_RESET}")
        for label, value in [
            ("Title", info.get("title", "")),
            ("Authors", ", ".join(aut.get("name", "") for aut in info.get("authors", []))),
            ("Identifier", info.get("identifier", "")),
            ("ISBN", info.get("isbn", "")),
            ("Publishers", ", ".join(pub.get("name", "") for pub in info.get("publishers", []))),
            ("Rights", info.get("rights", "")),
            ("Description", description[:500] + "..." if len(description) >= 500 else description),
            ("Release Date", info.get("issued", "")),
            ("URL", info.get("web_url", ""))
        ]:
            self.out(f"  {C_CYAN}{C_BOLD}{label:<14}{C_RESET} {value}")
        self.out(f"{C_DIM}{'─' * 40}{C_RESET}")

    def state(self, origin, done):
        progress = int(done * 100 / origin)
        bar_width = self.columns - 11
        filled = int(progress * bar_width / 100)
        if self.state_status.value < progress:
            self.state_status.value = progress
            if progress == 100:
                bar = f"{C_GREEN}{'█' * bar_width}{C_RESET}"
                pct = f"{C_GREEN}{C_BOLD} 100%{C_RESET}"
            else:
                bar = f"{C_GREEN}{'█' * filled}{C_DIM}{'░' * (bar_width - filled)}{C_RESET}"
                pct = f"{C_BOLD}{progress:4d}%{C_RESET}"
            sys.stdout.write(f"\r    {bar}{pct}" + ("\n" if progress == 100 else ""))

    def done(self, epub_file):
        self.out(f"\n{C_DIM}{'━' * 40}{C_RESET}")
        self.success("Done: %s" % epub_file)
        self.out(
            f"\n    If you like it, please {C_YELLOW}★{C_RESET} this project on GitHub:\n"
            f"        {C_DIM}https://github.com/lorenzodifuccia/safaribooks{C_RESET}\n"
            f"    Please don't forget to renew your subscription:\n"
            f"        {C_DIM}{SAFARI_BASE_URL}{C_RESET}\n"
        )
        self.out(f" {C_GREEN}{C_BOLD}✓{C_RESET}  Bye!\n")

    @staticmethod
    def api_error(response, status_code=None):
        message = "API: "
        if "detail" in response and "Not found" in response["detail"]:
            message += ("book's not present in Safari Books Online.\n"
                        "    The book identifier is the digits that you can find in the URL:\n"
                        "    `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`")
        else:
            # Only delete cookies on authentication failures, not transient errors
            if status_code in (401, 403) or status_code is None:
                if os.path.isfile(COOKIES_FILE):
                    os.remove(COOKIES_FILE)
            message += ("Out-of-Session%s.\n" % (
                " (%s)" % response["detail"]) if "detail" in response else "" +
                C_YELLOW + "›" + C_RESET +
                " Use the `--cred` or `--login` options in order to perform the auth login to Safari.")
        return message
