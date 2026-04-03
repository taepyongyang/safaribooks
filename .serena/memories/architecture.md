# Codebase Architecture

## File Structure
```
safaribooks-dev/
├── safaribooks_refactored.py  # Main CLI entry point
├── safaribooks_process.py     # Core SafariBooks class
├── safaribooks_display.py     # Display/logging class (color constants: C_RESET, C_GREEN, etc.)
├── safaribooks_config.py      # Configuration constants
├── safaribooks_diagnostics.py # DiagnosticCollector for --debug mode
├── pdf_renderer.py            # PDF rendering via headless Chromium (--pdf flag)
├── sso_cookies.py             # SSO cookie utility
├── safaribooks_winqueue.py    # Windows multiprocessing compat
├── requirements.txt           # pip dependencies
├── Pipfile                    # pipenv configuration
├── cookies.json               # Session cookies (gitignored)
└── Books/                     # Downloaded EPUBs/PDFs (gitignored)
```

## Module Responsibilities

### safaribooks_refactored.py
- CLI argument parsing with argparse
- Flags: --cred, --login, --no-cookies, --kindle, --debug, --convert, --pdf, --preserve-log
- Entry point that instantiates SafariBooks class

### safaribooks_process.py
**SafariBooks class** (~30+ methods):
- Authentication: `do_login()`, `check_login()`, `parse_cred()`
- Session management: `requests_provider()`, `handle_cookie_update()`
- Book retrieval: `get_book_info()`, `get_book_chapters()` (v2 API with adapter pattern)
- V2 helpers: `safe_json_response()`, `_extract_filename_from_reference_id()`, `_extract_href_from_reference_id()`, `_reshape_toc_v2_to_v1()`
- Content processing: `get_html()`, `parse_html()`, `link_replace()`
- Filename handling: `fix_duplicate_filenames()`, `build_filename_mapping()`
- Asset handling: `collect_css()`, `collect_css_assets()`, `collect_images()`, `get_cover()`
- Asset validation: `_validate_asset_path()`, `download_css_asset()`
- EPUB generation: `create_content_opf()`, `create_toc()`, `create_epub()`
- Post-processing: `run_conversion()` (--convert), `run_pdf_render()` (--pdf)
- Threading: `_thread_download_css()`, `_thread_download_images()`

### safaribooks_display.py
**Display class** + module-level color constants (C_RESET, C_BOLD, C_CYAN, etc.):
- Logging: `log()`, `out()`, `info()`, `error()`, `warn()`, `success()`
- UI output: `intro()`, `book_info()`, `state()`, `done()`
- Error handling: `exit()`, `unhandled_exception()`, `api_error()`
- Progress bar: Unicode blocks (█░) with green fill
- Color constants importable by other modules

### safaribooks_diagnostics.py
**DiagnosticCollector class**:
- Tracks download completeness when `--debug` enabled
- Compares expected vs actual counts for chapters, CSS, images
- Generates JSON diagnostic report with failure details

### pdf_renderer.py
- `is_converted_pdf()`: Detects pdf2htmlEX books via CSS markers
- `convert_to_pdf()`: Renders XHTML chapters to PDF via Playwright headless Chromium
- `get_spine_order()`: Parses content.opf for reading order
- `strip_epub_overrides()`: Removes injected CSS, adds page-break CSS
- `_detect_page_dimensions()`: Reads CSS for print/screen dimensions
- Optional deps: playwright, pypdf

### safaribooks_config.py
Configuration constants:
- URL endpoints (ORLY, Safari, API origins)
- File paths (PATH, COOKIES_FILE)
- Regex patterns (CSRF_TOKEN_RE, CHECK_EMAIL, CHECK_PWD)
- Debug settings (USE_PROXY, PROXIES)

## Data Flow
```
1. CLI args parsed (safaribooks_refactored.py)
2. SafariBooks.__init__ authenticates and retrieves book info
3. get_book_chapters() fetches chapter list (v2 API, paginated)
4. get() downloads all chapters, parsing HTML content
5. collect_css() / collect_images() download assets (threaded)
6. create_epub() generates final EPUB file
7. Optional: run_conversion() for Calibre cleanup (--convert)
8. Optional: run_pdf_render() for PDF output (--pdf)
9. Auto-detect: warns if converted PDF detected without --pdf
```

## Key Design Patterns
- Single class (SafariBooks) orchestrates entire workflow
- Display class handles all user-facing output with ANSI colors
- Configuration externalized to separate module
- Multi-threaded downloads for CSS and images
- V2 API adapter pattern: only fetch methods changed, all downstream code unchanged
- Platform-specific handling (WinQueue for Windows)

## Known EPUB Compliance Gaps
- ZIP structure: mimetype not first/uncompressed (needs manual zipfile loop)
- DOCTYPE: HTML5 instead of XHTML 1.1
- Font media types: EPUB 3 types without fallback chain
