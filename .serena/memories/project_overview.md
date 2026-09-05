# SafariBooks Project Overview

## Purpose
SafariBooks is a Python CLI tool for downloading and generating EPUB files from O'Reilly Learning (Safari Books Online). Authentication is browser-based: a logged-in Chrome driven via CDP (`safaribooks_browser_transport.py`) routes all content requests, because Akamai 403s plain `requests`. Saved `cookies.json` is injected for auto-login; if stale, cookies are cleared and the user logs in manually once. `--cred`/`--login` are deprecated (fall back to browser auth). See `mem:session_2026-08-30_stale_cookie_login_fix`.

## Tech Stack
- **Language**: Python 3.6+
- **Package Manager**: pipenv (preferred) or pip
- **Core Dependencies**:
  - `lxml` - HTML/XML parsing for book content
  - `requests` - HTTP client for API communication
  - `urllib3` - URL handling
- **Standard Library**: json (cookies/metadata), zipfile (EPUB generation), argparse (CLI)

## Key Features
- Browser-routed transport (Chrome via CDP) — Akamai bypass; auto-login from saved cookies, manual login fallback
- SSO cookie support for enterprise/university logins (`sso_cookies.py`)
- Kindle-compatible CSS option (`--kindle` appends KINDLE_HTML; the earlier inversion bug is fixed)
- Sequential CSS/image downloads (by design — avoids Akamai bot detection)
- CSS asset downloading (fonts, icons referenced in stylesheets)
- EPUB generation with proper metadata
- Diagnostic system (--debug flag) for tracking download completeness
- EPUB filename uses title and author format

## Important Notes
- Downloads copyrighted content - use only in compliance with O'Reilly Terms of Service
- Session cookies persisted in `cookies.json`
- Books saved to `Books/` directory
- Unit tests in `tests/` (pytest, 47 tests; see `mem:session_2026-09-05_structural_cleanup`); browser transport and EPUB packaging are verified manually

## Recent Improvements (2026-02-24)
- Migrated from retired v1 API to v2 API using adapter pattern (all changes in safaribooks_process.py)
- Added safe_json_response() to prevent JSONDecodeError crashes
- Fixed session validation (switched from PROFILE_URL to v2 search API)
- V2 uses offset pagination, split metadata endpoints, different TOC format
- CRITICAL: expired orm-jwt returns HTTP 200 with truncated preview content (no error code)

## Recent Improvements (2025-12-23)
- Fixed duplicate filename handling for chapters
- Added internal link rewriting with filename mapping
- Implemented CSS asset (fonts/icons) downloading
- Fixed manifest generation to only count .css files
- Added title_author.epub naming convention
