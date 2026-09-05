# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SafariBooks is a Python CLI that downloads a book from O'Reilly Learning (Safari Books Online) and assembles it into an EPUB (optionally a PDF). It is a fork of the unmaintained `lorenzodifuccia/safaribooks`, heavily reworked: the retired v1 API was replaced by v2, and all content traffic now goes through a real logged-in Chrome because O'Reilly's Akamai bot protection blocks plain `requests`.

`--cred`/`--login` are deprecated and silently fall back to browser auth. Authentication is browser-based only.

## Development Commands

```bash
# Install (pyenv virtualenv `safaribooks` is set in .python-version; Pipfile targets 3.11)
pip3 install -r requirements.txt
# or: pipenv install && pipenv shell

# Download a book. Opens Chrome; auto-logs in from cookies.json, else prompts you to log in
# and press ENTER. Must run interactively — the login prompt is a blocking input().
python3 safaribooks_refactored.py <BOOK_ID>

# Debugging an incomplete download: diagnostics report + keep the log
python3 safaribooks_refactored.py --debug --preserve-log <BOOK_ID>

# Seed cookies.json manually from a cookie string copied out of the browser
python3 sso_cookies.py "cookie_string_from_browser"

# Lint / syntax (ruff is pinned in requirements.txt; no config file, defaults apply)
ruff check .
pytest                    # characterization tests for the pure helpers (no network)
python3 -m py_compile *.py
```

Unit tests in `tests/` cover the pure helpers (filename fixing, link rewriting, v2→v1 reshaping, TOC, CSS asset parsing, expired-JWT detection) by constructing `SafariBooks` via `__new__` with stub collaborators — see `tests/conftest.py`. They do not cover the browser transport or EPUB packaging; those are verified manually: download a book with `--debug`, read the diagnostic report, then open the EPUB in Calibre.

### CLI flags

| Flag | Effect |
|------|--------|
| `--debug` | Enable `DiagnosticCollector`; writes `diagnostic_report_<ID>.json` and prints a completeness summary |
| `--kindle` | Append `KINDLE_HTML` CSS (word-wrap, `pre-wrap` on tables/pre) so code doesn't overflow on e-readers |
| `--convert` | After download, run `scripts/convert-epub.sh` (Calibre epub→mobi→epub round-trip); output `<name>.final.epub` |
| `--pdf` | Render OEBPS to PDF via headless Chromium. Optional deps: `pip install playwright pypdf && playwright install chromium` |
| `--no-cookies` | Don't write the browser's session cookies back to `cookies.json` at the end |
| `--preserve-log` | Keep `info_<ID>.log`; by default it is deleted on a clean run |

Book IDs must match `^[0-9]{10,13}$` (validated in `SafariBooks.__init__`).

## Architecture

Everything is orchestrated from `SafariBooks.__init__` in `safaribooks_process.py`; constructing the object runs the whole pipeline. There is no separate `run()`.

```
safaribooks_refactored.py        argparse → SafariBooks(args)
safaribooks_process.py           SafariBooks: the entire pipeline (~2000 lines)
safaribooks_browser_transport.py BrowserTransport + BrowserResponse (CDP-routed HTTP)
safaribooks_browser_auth.py      Chrome discovery/launch helpers (find_chrome_path, launch, wait for CDP)
safaribooks_diagnostics.py       DiagnosticCollector (only active with --debug)
safaribooks_display.py           Display: progress bar, log file, ANSI colours (C_* constants)
safaribooks_config.py            Paths, hosts, SAFARI_BASE_URL, CHROME_PROFILE_DIR
pdf_renderer.py                  --pdf implementation (Playwright); imported lazily
sso_cookies.py                   Cookie-string → cookies.json helper
register_user.py                 Legacy account-registration script; not part of the pipeline
```

### Pipeline (order in `SafariBooks.__init__`)

1. `BrowserTransport.start()` launches Chrome, injects `cookies.json`, and confirms login. If the saved cookies don't yield a session it **clears all browser cookies** before prompting for manual login (stale cookies make O'Reilly's sign-in reset silently).
2. `check_login()` hits `API_V2_SEARCH` as a lightweight auth probe.
3. `get_book_info()` → `get_book_chapters()` (offset pagination, 100/page, recursive) → `fix_duplicate_filenames()` → `build_filename_mapping()`.
4. `get()` walks `chapters_queue` (a `deque`), calling `get_html()` → `parse_html()` → `link_replace()` → `save_page_html()`. Cover chapters are moved to the front; a default cover is synthesised if none was found.
5. `collect_css()` → `collect_css_assets()` (fonts/icons referenced by `url()` in CSS) → `collect_images()`.
6. `create_epub()` writes `mimetype`, `META-INF/container.xml`, `OEBPS/content.opf`, `OEBPS/toc.ncx`, then zips via `shutil.make_archive` and renames to `<title>_<author>.epub`.
7. Cookies are saved back to `cookies.json` (0600), Chrome is closed, then optional `--convert` / `--pdf` post-processing. Without `--pdf`, `pdf_renderer.is_converted_pdf()` still runs to warn when a book is a fixed-layout pdf2htmlEX conversion.

### Browser transport (the Akamai constraint)

O'Reilly's content endpoints (`/api/v2/epubs/...`, chapters, files) return `403 AkamaiGHost` to any non-browser client. This is fingerprint-bound: byte-identical cookies from `requests` still get 403 while an in-page `fetch()` returns 200. Therefore:

- `requests_provider()` routes **every request** through `BrowserTransport.fetch()` and returns a `BrowserResponse` (`status_code`, `text`, `content`, `headers`, `json()`, `iter_content()`) or `None` on transport failure. There is no `requests.Session` fallback any more; callers check `is None`.
- `fetch()` follows redirects itself, so `BrowserResponse.is_redirect` is always `False` and callers never see 3xx responses.
- Chrome runs with a throwaway profile at `/tmp/safaribooks_chrome_profile` and `--remote-allow-origins=*`; `websocket-client` is required. `close()` is registered with `atexit` so an abort never orphans Chrome.
- A content **403 is a bot block, not an expired session**. An expired `orm-jwt` instead returns HTTP 200 with a ~2 KB preview page; `get_html()` detects this (body < 3000 bytes with no `sbo-rt-content`) and records a `VALIDATION` failure.

### v2 API adapter pattern

`get_book_info()`, `get_book_chapters()`, and `create_toc()` fetch v2 and reshape results into the **v1 dict shape** the rest of the code expects (`title`, `filename`, `content`, `asset_base_url`, `images` as paths relative to `API_V2_FILES`, `stylesheets` as `[{"url": ...}]`, `site_styles`). `_reshape_toc_v2_to_v1()` does the same for the TOC. When touching API code, keep that shape intact so `parse_html`, `link_replace`, `parse_toc`, and EPUB generation stay untouched.

### Things that are easy to get wrong

- **Downloads are sequential by design.** `_thread_download_css/_images` are named for history but are called in a plain loop to avoid tripping bot detection. Don't parallelise.
- **`create_content_opf()` re-reads `self.css` and `self.images` from the filesystem.** The O(1) dedup companions (`_css_index`, `_image_urls`, `_image_basenames`) are only valid during the download phase.
- **Non-fatal chapter failures.** `get_html()` returns `None` and `get()` skips the chapter; 401/403 on a chapter is fatal. Failures are only visible in the diagnostics report or log.
- **`display.last_request` dumps the full request/response** (including cookies) into the log on error. This is intentional for debugging; leave it.
- **Chapter count vs recursion limit.** `get_book_chapters()` raises `sys.setrecursionlimit` to the chapter count because `parse_toc` recurses.
- **Windows.** Platform checks use `sys.platform == "win32"` (not `"win" in sys.platform`, which matched `darwin`). `WinQueue` replaces `queue.Queue` there.
- **pdf_renderer is imported inside methods**, not at module top, so Playwright stays optional.

### Output layout

```
Books/<Title> (<ID>)/
├── <title>_<author>.epub          (+ .final.epub with --convert, .pdf with --pdf)
├── diagnostic_report_<ID>.json    (--debug only)
├── OEBPS/  *.xhtml, content.opf, toc.ncx, Styles/ (Style00.css, fonts, icons), Images/
├── META-INF/container.xml
└── mimetype
```

Re-running on an existing directory reuses already-downloaded chapter/CSS/image files; delete the directory to force a clean fetch.

## Known EPUB compliance gaps

`shutil.make_archive` does not store `mimetype` first/uncompressed; chapter DOCTYPE is HTML5 rather than XHTML 1.1; font media types are EPUB 3 only; NCX `navPoint` ids may start with a digit. Calibre's `ebook-convert` tolerates all of these, which is why `--convert` exists.

## Project memory

`.serena/memories/` holds per-session change notes (e.g. `session_2026-02-24_v2_api_migration.md`, `session_2026-08-30_stale_cookie_login_fix.md`) with the reasoning behind non-obvious decisions. Check there before re-investigating API or auth behaviour.
