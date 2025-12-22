# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SafariBooks is a Python CLI tool for downloading and generating EPUB files from O'Reilly Learning (Safari Books Online). Users authenticate via credentials or SSO cookies extracted from browser sessions.

**Note**: Direct login via the script no longer works due to O'Reilly API changes. Use SSO cookie method instead.

## Development Commands

```bash
# Install dependencies
pip3 install -r requirements.txt
# Or with pipenv (preferred)
pipenv install && pipenv shell

# Download a book (SSO method - most common)
python3 safaribooks_refactored.py <BOOK_ID>

# Download with credentials
python3 safaribooks_refactored.py --cred "email:password" <BOOK_ID>

# Create cookies.json from browser SSO cookies
python3 sso_cookies.py "cookie_string_from_browser"

# Enable diagnostic mode for debugging incomplete downloads
python3 safaribooks_refactored.py --debug <BOOK_ID>
```

### CLI Options
- `--debug`: Enable diagnostics - generates `diagnostic_report_<BOOK_ID>.json` with download completeness tracking
- `--kindle`: **WARNING: Logic is inverted** - currently REMOVES Kindle-friendly CSS instead of adding it
- `--no-cookies`: Don't persist session to `cookies.json`
- `--preserve-log`: Keep log file even on success

### Post-Download
Convert raw EPUB to clean format with Calibre:
```bash
ebook-convert "input.epub" "output.epub"
# Or for Kindle: convert to AZW3/MOBI with "Ignore margins" option
```

## Code Architecture

### Data Flow
```
CLI (safaribooks_refactored.py)
    └── SafariBooks class (safaribooks_process.py)
            ├── Authentication → O'Reilly API
            ├── get_book_info() → Book metadata
            ├── get_book_chapters() → Chapter list (paginated API)
            ├── get() → Download all chapter HTML
            │     └── parse_html() → Extract/rewrite content
            │           └── link_replace() → Rewrite internal links
            ├── collect_css() → Download stylesheets
            │     └── collect_css_assets() → Download fonts/icons from CSS
            ├── collect_images() → Download images
            └── create_epub() → Generate EPUB package
                  ├── create_content_opf() → Manifest
                  └── create_toc() → Navigation
```

### Key Classes

**SafariBooks** (`safaribooks_process.py`): Core orchestrator handling the complete download-to-EPUB pipeline. Key methods:
- `fix_duplicate_filenames()`: Resolves duplicate chapter filenames (e.g., multiple `index.xhtml`)
- `build_filename_mapping()`: Maps original paths to new unique filenames for internal link rewriting
- `link_replace()`: Rewrites HTML links using the filename mapping
- `parse_css_for_assets()`: Extracts font/icon URLs from CSS `url()` references
- `generate_epub_filename()`: Creates `title_author.epub` filename with safe characters

**DiagnosticCollector** (`safaribooks_diagnostics.py`): Tracks download completeness when `--debug` is enabled. Compares expected vs actual counts for chapters, CSS, and images. Generates JSON report with failure details.

**Display** (`safaribooks_display.py`): Progress bars, logging, and terminal output.

### EPUB Structure Generated
```
Books/<Title> (<ID>)/
├── OEBPS/
│   ├── content.opf      # Manifest and metadata
│   ├── toc.ncx          # Navigation
│   ├── *.xhtml          # Chapter content
│   ├── Styles/
│   │   ├── Style00.css  # Stylesheets
│   │   ├── *.ttf        # Fonts from CSS
│   │   └── *.png        # Icons from CSS
│   └── Images/          # Content images
├── META-INF/container.xml
└── mimetype
```

## Known Issues

1. **Kindle flag inverted**: `--kindle` removes helpful CSS rules instead of adding them. The `KINDLE_HTML` CSS (word-wrap, pre-wrap for tables/pre) is included by DEFAULT and removed when flag is passed.

2. **No horizontal scroll on Kindle**: Kindle e-readers cannot scroll horizontally. The `white-space: pre-wrap` and `word-break: break-word` rules in `KINDLE_HTML` prevent code/tables from overflowing.

## Testing

No automated tests. Manual testing:
1. Download a book with `--debug`
2. Check `diagnostic_report_<ID>.json` for completeness
3. Convert with `ebook-convert` and verify no missing file warnings
