# Session: CSS Asset Download & Kindle Flag Fix
**Date**: 2025-12-23
**Duration**: Extended session continuing from previous context

## Summary
Implemented CSS asset downloading for fonts and icons referenced in stylesheets, and identified a logic bug in the `--kindle` flag.

## Key Discoveries

### 1. CSS Asset Download Implementation
**Problem**: ebook-convert reported missing fonts (DejaVu*.ttf, NotoSansMono*.ttf) and icons (note.png, tip.png, caution.png) referenced in CSS files.

**Solution Implemented** (safaribooks_process.py):
- `parse_css_for_assets()` - Parses CSS files for `url()` references (lines 1057-1093)
- `download_css_asset()` - Downloads individual font/image assets (lines 1095-1137)
- `collect_css_assets()` - Coordinates parsing and downloading (lines 1139-1172)
- Updated `__init__` to call `collect_css_assets()` after CSS download
- Updated `create_content_opf()` to include CSS assets in manifest with proper MIME types

**Critical Bug Fixed**: `create_content_opf()` was counting ALL files in Styles/ directory (including downloaded PNGs) as CSS files, causing manifest entries like Style01.css-Style14.css that didn't exist.
```python
# Fixed: Filter to only .css files
self.css = [f for f in next(os.walk(self.css_path))[2] if f.endswith('.css')]
```

### 2. Kindle Flag Logic Inversion (IDENTIFIED, NOT FIXED)
**Problem**: The `--kindle` flag behavior is backwards.

**Current Logic** (line 206):
```python
self.BASE_HTML = self.BASE_01_HTML + (self.KINDLE_HTML if not args.kindle else "") + self.BASE_02_HTML
```
- WITHOUT `--kindle`: Kindle CSS rules ARE included
- WITH `--kindle`: Kindle CSS rules are EXCLUDED

**Research Findings**:
- Kindle cannot scroll horizontally - content overflow is cut off
- `white-space: pre-wrap` and `word-break: break-word` ARE needed for Kindle
- The KINDLE_HTML CSS rules help prevent overflow on `<pre>` and `<table>` elements

**Correct Behavior**: Flag should ADD rules when passed, not remove them.

## Files Modified
- `safaribooks_process.py`:
  - Added 3 new methods for CSS asset handling
  - Fixed CSS file filtering in `create_content_opf()`
  - Added `self.css_asset_paths` initialization
  - Added `collect_css_assets()` call in `__init__`

## Pending Work
- Fix the `--kindle` flag logic inversion (awaiting user confirmation)

## Technical Notes
- CSS assets stored in `OEBPS/Styles/` (flat, not in subdirectories like fonts/)
- Manifest entries use MIME types: font/ttf, font/otf, font/woff, image/png, etc.
- `shutil.make_archive()` automatically includes subdirectories in EPUB
