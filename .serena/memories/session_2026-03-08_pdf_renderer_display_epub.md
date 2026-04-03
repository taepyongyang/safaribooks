# Session 2026-03-08: PDF Renderer, Display Overhaul, EPUB Compliance

## Features Added

### PDF Renderer (`pdf_renderer.py` — new file)
- `--pdf` CLI flag renders scanned/converted books (pdf2htmlEX) to PDF via headless Chromium
- Uses Playwright `page.pdf()` with print-mode CSS dimensions (pt → inches conversion)
- Strips injected EPUB override CSS, injects page-break CSS for proper pagination
- Merges per-chapter PDFs with pypdf, sets title/author metadata
- Reuses single browser page across all chapters for performance
- Detects page dimensions: prefers @media print (pt→in), falls back to screen (px), then image dimensions
- Skips `default_cover.xhtml` (blurry EPUB thumbnail — actual cover is first pdf2htmlEX page)
- Optional deps: `playwright` + `pypdf` (graceful error if missing)

### Auto-Detection of Converted PDFs
- `is_converted_pdf(oebps_dir)` checks Style00.css for pdf2htmlEX markers (#pdf-main, .pf, .t)
- When detected without --pdf flag, prints recommendation to re-run with --pdf
- Zero false positives on normal reflowable books

### Display Overhaul (`safaribooks_display.py`)
- **BUG FIX**: `"win" not in sys.platform` was False on macOS because "darwin" contains "win" — colors were silently disabled on macOS the entire time. Fixed with `sys.platform == "win32"` exact match.
- Extended color palette: cyan, green, magenta, blue, bold, dim (was just yellow + red bg)
- Unicode progress bar: `████░░░░` green fill (was `####----` yellow bg)
- Colored status indicators: `›` info, `▶` phase, `✓` success, `✗` error, `⚠` warning
- Color gradient banner cycling cyan/blue/magenta per line
- Boxed book info with aligned labels, phase separators between stages
- New convenience methods: `warn()`, `success()`
- Module-level color constants (C_RESET, C_GREEN, etc.) importable by other modules

### EPUB Spec Compliance Fixes (7 trivial non-regressive fixes)
1. **dtb:uid mismatch**: Removed `ID:ISBN:` prefix in NCX — now matches OPF dc:identifier
2. **Missing `<title>` in `<head>`**: Added `<title></title>` to BASE_01_HTML template
3. **NCX XML escaping**: Wrapped title/author with `escape()` in `create_toc()` — prevents malformed XML on titles with `&`, `<`
4. **container.xml encoding**: Added `encoding="utf-8"` to XML declaration
5. **NCX standalone**: Removed `standalone="no"` — prevents DTD fetch attempts
6. **Empty cover meta**: Conditionally emit `<meta name="cover">` only when cover ID exists
7. **dc:language**: Pull from v2 API `language` field with `en-US` fallback (was hardcoded)

### Dependency Upgrades (security + maintenance)
- certifi 2024.12.14 → 2026.2.25 (CA cert bundle freshness)
- urllib3 2.3.0 → 2.6.3 (decompression bomb CVE fix)
- lxml 5.3.0 → 5.3.2 (CVE-2025-24928)
- requests 2.32.3 → 2.32.5 (bug fixes)
- charset-normalizer 3.4.1 → 3.4.5 (CJK detection improvements)
- idna 3.10 → 3.11

## Known Remaining EPUB Issues (not yet fixed)
- **ZIP structure**: `shutil.make_archive()` doesn't put mimetype first/uncompressed (OCF §3.3). Fix requires manual zipfile loop.
- **DOCTYPE**: `<!DOCTYPE html>` (HTML5) instead of XHTML 1.1 doctype
- **Font media types**: Uses EPUB 3 types (`font/ttf`) instead of EPUB 2 (`application/vnd.ms-opentype`), no fallback chain
- **navPoint ID**: May start with digits (invalid XML Name)
- **XHTML2 schemaLocation**: Points to abandoned XHTML 2.0 namespace

## Technical Notes
- Playwright `page.pdf()` only accepts px, in, cm, mm — NOT pt. Must convert pt→inches (÷72).
- pdf2htmlEX books have dual CSS: screen (px) and @media print (pt). Must use print dimensions for page.pdf().
- XHTML preservation: Must use regex string replacement, not lxml DOM parsing (lxml breaks self-closing tags).
- O'Reilly sandbox restriction: `learning.oreilly.com` not in allowed hosts, needs `dangerouslyDisableSandbox`.
