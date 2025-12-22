# SafariBooks Project Overview

## Purpose
SafariBooks is a Python CLI tool for downloading and generating EPUB files from O'Reilly Learning (Safari Books Online). It allows users to download books using either email/password credentials or SSO cookies for personal and educational use.

## Tech Stack
- **Language**: Python 3.6+
- **Package Manager**: pipenv (preferred) or pip
- **Core Dependencies**:
  - `lxml` - HTML/XML parsing for book content
  - `requests` - HTTP client for API communication
  - `urllib3` - URL handling
- **Standard Library**: json (cookies/metadata), zipfile (EPUB generation), argparse (CLI)

## Key Features
- Credential-based authentication
- SSO cookie support for enterprise/university logins
- Kindle-compatible CSS options (note: --kindle flag logic is inverted - see session_2025-12-23)
- Multi-threaded CSS/image downloads
- CSS asset downloading (fonts, icons referenced in stylesheets)
- EPUB generation with proper metadata
- Diagnostic system (--debug flag) for tracking download completeness
- EPUB filename uses title and author format

## Important Notes
- Downloads copyrighted content - use only in compliance with O'Reilly Terms of Service
- Session cookies persisted in `cookies.json`
- Books saved to `Books/` directory
- No formal test suite exists

## Recent Improvements (2025-12-23)
- Fixed duplicate filename handling for chapters
- Added internal link rewriting with filename mapping
- Implemented CSS asset (fonts/icons) downloading
- Fixed manifest generation to only count .css files
- Added title_author.epub naming convention
