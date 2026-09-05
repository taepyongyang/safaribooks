# Suggested Commands for SafariBooks Development

## Installation

```bash
# Using pip
pip3 install -r requirements.txt

# Using pipenv (preferred)
pipenv install && pipenv shell
```

## Running the Application

```bash
# Download a book (opens Chrome; auto-logs in from cookies.json, else prompts for manual login)
python3 safaribooks_refactored.py <BOOK_ID>

# With diagnostics + kept log (preferred when debugging; run interactively — login prompt is input())
python3 safaribooks_refactored.py --debug --preserve-log <BOOK_ID>

# --cred / --login are DEPRECATED (O'Reilly API changed); they fall back to browser auth
```

## CLI Options
- `--debug` - Diagnostic report (`diagnostic_report_<ID>.json`) with completeness tracking
- `--convert` - Post-process EPUB with Calibre `ebook-convert`
- `--pdf` - Render fixed-layout (pdf2htmlEX) books to PDF via Playwright
- `--kindle` - Add CSS rules for Kindle compatibility
- `--no-cookies` - Don't save session cookies
- `--preserve-log` - Keep log files even without errors

## SSO Cookie Setup

```bash
# Create SSO cookies file from browser cookie string
python3 sso_cookies.py "cookie_string_from_browser"
```

## System Utilities (Darwin/macOS)

```bash
# Directory listing
ls -la

# Find files
find . -name "*.py" -type f

# Search in files
grep -r "pattern" --include="*.py" .

# Git operations
git status
git diff
git log --oneline -10
```

## Development Notes
- No linting/formatting tools configured
- Automated tests via pytest (see `tests/`)
- Manual testing by downloading sample books and verifying EPUB output
