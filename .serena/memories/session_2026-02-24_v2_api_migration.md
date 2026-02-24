# Session: V2 API Migration (2026-02-24)

## Problem
O'Reilly retired v1 API entirely — all v1 endpoints return 404. Users see `JSONDecodeError: Expecting value: line 1 column 1` because API returns HTML error pages instead of JSON.

## Solution: Adapter Pattern Migration
All changes in `safaribooks_process.py` only. Rewrote API-fetching methods to use v2, reshaping responses to v1 format so downstream code (parse_html, link_replace, EPUB generation) is untouched.

### V2 Endpoint Constants (replaced API_TEMPLATE at line ~50)
```
API_V2_EPUBS    = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/"
API_V2_CHAPTERS = SAFARI_BASE_URL + "/api/v2/epub-chapters/?epub_identifier=urn:orm:book:{0}&limit=100&offset={1}"
API_V2_TOC      = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/table-of-contents/"
API_V2_SEARCH   = SAFARI_BASE_URL + "/api/v2/search/?query={0}&limit=1"
API_V2_FILES    = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/files"
```

### Methods Added
- `safe_json_response()` — wraps .json() with status-specific error messages
- `_extract_filename_from_reference_id()` — e.g. `9781633437333-/Text/preface.html` → `preface.html`
- `_extract_href_from_reference_id()` — e.g. `9781633437333-/Text/preface.html` → `Text/preface.html`
- `_reshape_toc_v2_to_v1()` — recursive v2→v1 TOC transformation

### Methods Rewritten
- `get_book_info()` — fetches v2 epubs + search APIs, reshapes to v1 format
- `get_book_chapters()` — offset pagination, v1 reshaping (images: absolute→relative, stylesheets: strings→dicts)
- `create_toc()` — uses v2 TOC endpoint
- `check_login()` / `validate_session()` — switched from PROFILE_URL to v2 search API

### V2 Key Differences
- Pagination: offset-based (`?offset=N&limit=M`) not page-based
- Book metadata split across epubs + search endpoints
- Chapter images: full absolute URLs (must strip `/api/v2/epubs/.../files/` prefix)
- Chapter stylesheets: plain URL strings, not `{"url": "..."}` dicts
- TOC: `title`/`reference_id` instead of `label`/`href`

## Critical Discovery: Expired JWT = Silent Truncation
- V2 API returns HTTP 200 with truncated preview HTML (~2KB ending with "...") when `orm-jwt` expired
- NO error code — appears successful but content is incomplete
- `file_size` field from `/files/?limit=N` listing shows expected size — compare to detect truncation
- Fix: refresh cookies via `python3 sso_cookies.py "<cookie_string>"`

## Validation
- Bulletproof Problem Solving (9781119553021): 22/22 chapters, byte-for-byte identical with backup
- ML Platform Engineering (9781633437333): 30/30 chapters, 190 images, 100% success

## Reference Implementation
- `/Users/kimt/Projects/safaribooksv2/src/epub.py` — alternative v2 impl using files listing API
- Uses `browser_cookie3` for auth, `/files/?limit=N` for all files, downloads by `kind`

## Other Fixes
- `safe_json_response()` prevents JSONDecodeError crashes with actionable error messages
- Session validation switched from PROFILE_URL (caused 302 redirect) to v2 search API
