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
# Download book using email:password credentials
python3 safaribooks_refactored.py --cred "email:password" <BOOK_ID>

# Download using interactive login prompt
python3 safaribooks_refactored.py --login <BOOK_ID>

# Download using SSO cookies (requires cookies.json file)
python3 safaribooks_refactored.py <BOOK_ID>
```

## CLI Options
- `--cred "email:password"` - Use credentials for login
- `--login` - Interactive login prompt
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
- No automated testing framework
- Manual testing by downloading sample books and verifying EPUB output
