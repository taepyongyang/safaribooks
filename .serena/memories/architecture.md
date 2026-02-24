# Codebase Architecture

## File Structure
```
safaribooks-dev/
├── safaribooks_refactored.py  # Main CLI entry point
├── safaribooks_process.py     # Core SafariBooks class
├── safaribooks_display.py     # Display/logging class
├── safaribooks_config.py      # Configuration constants
├── sso_cookies.py            # SSO cookie utility
├── safaribooks_winqueue.py   # Windows multiprocessing compat
├── requirements.txt          # pip dependencies
├── Pipfile                   # pipenv configuration
├── cookies.json              # Session cookies (gitignored)
└── Books/                    # Downloaded EPUBs (gitignored)
```

## Module Responsibilities

### safaribooks_refactored.py
- CLI argument parsing with argparse
- Credential parsing and validation
- Entry point that instantiates SafariBooks class

### safaribooks_process.py
**SafariBooks class** (~30 methods):
- Authentication: `do_login()`, `check_login()`, `parse_cred()`
- Session management: `requests_provider()`, `handle_cookie_update()`
- Book retrieval: `get_book_info()`, `get_book_chapters()` (v2 API with adapter pattern)
- V2 helpers: `safe_json_response()`, `_extract_filename_from_reference_id()`, `_extract_href_from_reference_id()`, `_reshape_toc_v2_to_v1()`
- Content processing: `get_html()`, `parse_html()`, `link_replace()`
- Filename handling: `fix_duplicate_filenames()`, `build_filename_mapping()`
- Asset handling: `collect_css()`, `collect_css_assets()`, `collect_images()`, `get_cover()`
- Asset validation: `_validate_asset_path()`, `download_css_asset()`
- EPUB generation: `create_content_opf()`, `create_toc()`, `create_epub()`
- Threading: `_thread_download_css()`, `_thread_download_images()`

### safaribooks_diagnostics.py
**DiagnosticCollector class**:
- Tracks download completeness when `--debug` enabled
- Compares expected vs actual counts for chapters, CSS, images
- Generates JSON diagnostic report with failure details

### safaribooks_display.py
**Display class** (16 methods):
- Logging: `log()`, `out()`, `info()`, `error()`
- UI output: `intro()`, `book_info()`, `state()`, `done()`
- Error handling: `exit()`, `unhandled_exception()`, `api_error()`

### safaribooks_config.py
Configuration constants:
- URL endpoints (ORLY, Safari, API origins)
- File paths (PATH, COOKIES_FILE)
- Regex patterns (CSRF_TOKEN_RE, CHECK_EMAIL, CHECK_PWD)
- Debug settings (USE_PROXY, PROXIES)

### sso_cookies.py
- `transform()` function: Converts browser cookie string to cookies.json format

## Data Flow
```
1. CLI args parsed (safaribooks_refactored.py)
2. SafariBooks.__init__ authenticates and retrieves book info
3. get_book_chapters() fetches chapter list
4. get() downloads all chapters, parsing HTML content
5. collect_css() / collect_images() download assets (threaded)
6. create_epub() generates final EPUB file
7. Output saved to Books/<title>/<bookid>.epub
```

## Key Design Patterns
- Single class (SafariBooks) orchestrates entire workflow
- Display class handles all user-facing output
- Configuration externalized to separate module
- Multi-threaded downloads for CSS and images
- Platform-specific handling (WinQueue for Windows)
