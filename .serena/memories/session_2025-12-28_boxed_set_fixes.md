# Session: Boxed Set & Manifest Fixes (2025-12-28)

## Issues Addressed

### 1. Duplicate Manifest Entry for Chapters (Boxed Sets)
**Problem**: Books bundled as boxed sets (e.g., HBR's 10 Must Reads - 6 Books) have identical internal structures. Multiple books with `xhtml/cover.xhtml` all got renamed to `xhtml_cover.xhtml`.

**Root Cause**: `fix_duplicate_filenames()` only used parent directory as prefix, but boxed set books share identical directory structures.

**Fix** (`safaribooks_process.py:546-622`):
- Added **second pass** that detects remaining duplicates after first rename
- Adds numeric suffixes (`_1`, `_2`, etc.) to make them unique:
  - `xhtml_cover.xhtml` (first book, unchanged)
  - `xhtml_cover_1.xhtml` (second book)
  - `xhtml_cover_2.xhtml` (third book)
- Converted from `@staticmethod` to regular method for debug logging
- Added comprehensive debug output with `--debug` flag

### 2. Duplicate Image Manifest IDs (titlepage.png blocked)
**Problem**: Both `titlepage.jpg` and `titlepage.png` generated same manifest ID `img_titlepage`, causing PNG to be skipped.

**Fix** (`safaribooks_process.py:1505-1523`):
- Include extension in manifest ID: `img_titlepage_jpg`, `img_titlepage_png`
- Updated cover manifest ID generation to match

### 3. Safety Check in create_content_opf
**Added** (`safaribooks_process.py:1449-1503`):
- Duplicate chapter ID/filename detection with debug logging
- Skips duplicates to prevent invalid EPUB manifest

## Known Limitations

### Hyperlink Warnings in Boxed Sets
**Issue**: Internal links point to wrong file versions after deduplication.
- Link: `xhtml_007_chapter_003.xhtml#ji_302`
- Anchor `#ji_302` actually exists in `xhtml_007_chapter_003_1.xhtml` or `_2.xhtml`

**Cause**: Cross-references between chapters in different books within boxed set can't be resolved without knowing which "book" each chapter belongs to.

**Impact**: Cosmetic - book content is complete and readable, but some page number references won't navigate correctly.

**Fix Complexity**: Would require tracking which "book" each chapter belongs to and resolving links within that context. Significant architectural change.

### Calibre "cover.xhtml not found" Warning
**Issue**: Warning during MOBI→EPUB round-trip conversion.

**Cause**: MOBI format doesn't preserve HTML cover file, only cover image. When converting back to EPUB, Calibre looks for referenced `cover.xhtml` but it's not in MOBI.

**Impact**: Cosmetic - final output has cover image correctly.

## Files Modified
- `safaribooks_process.py`:
  - `fix_duplicate_filenames()` - Two-pass deduplication with numeric suffixes
  - `create_content_opf()` - Duplicate detection, extension in image IDs
  - `build_filename_mapping()` - No changes (works correctly)

### 4. Dotted Filename Manifest ID Collisions (2025-12-30)
**Problem**: Files with dots in the name (e.g., `11.9.png` for Chapter 11, Figure 9) generated manifest IDs that collided with similar files without dots.

**Example**:
- `11.9.png` → split(".") → ["11", "9", "png"] → base="119" → ID=`img_119_png`
- `119.png` → split(".") → ["119", "png"] → base="119" → ID=`img_119_png`
- Both files exist on disk, but second is skipped in manifest due to duplicate ID

**Symptom**: Calibre warning `Referenced file 'OEBPS/Images/11.9.png' not in manifest`

**Fix** (`safaribooks_process.py:1507-1518`):
- Changed from `split(".")` to `rsplit(".", 1)` to split only on LAST dot
- Replace dots with underscores in base_name to create valid XML IDs
- Result: `11.9.png` → ID=`img_11_9_png`, `119.png` → ID=`img_119_png` (unique)

**Affected Books**: Any book using chapter.figure notation for image filenames (e.g., technical/programming books)

## Testing Notes
- Boxed set: `9798892792905` (HBR's 10 Must Reads - 6 Books, 142 chapters)
- Regular book: `9781394325412` (Data Engineering for Beginners)
- Dotted filenames: `9798888651889` (A Common-Sense Guide to Data Structures and Algorithms in Python, Volume 2)
- Both convert successfully with cosmetic warnings only
