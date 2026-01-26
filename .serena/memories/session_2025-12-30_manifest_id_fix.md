# Session: Dotted Filename Manifest ID Fix (2025-12-30)

## Issue Addressed

### Dotted Filename Manifest ID Collisions
**Problem**: Files with dots in the name (e.g., `11.9.png` for Chapter 11, Figure 9) generated manifest IDs that collided with similar files without dots.

**Symptom**: Calibre warning during EPUB conversion:
```
Referenced file 'OEBPS/Images/11.9.png' not in manifest
Referenced file 'OEBPS/Images/1.18.png' not in manifest
...
```

**Root Cause** (`safaribooks_process.py:1507-1512`):
```python
dot_split = i.split(".")           # Splits on ALL dots
base_name = "".join(dot_split[:-1]) # Joins all parts, losing dots
```

This caused ID collisions:
| Filename | split(".") | base_name | Manifest ID |
|----------|------------|-----------|-------------|
| `11.9.png` | ["11", "9", "png"] | "119" | `img_119_png` |
| `119.png` | ["119", "png"] | "119" | `img_119_png` |

Both files exist on disk (downloaded successfully), but the duplicate ID check skips the second file from the manifest.

## Fix Applied

**Location**: `safaribooks_process.py:1507-1518`

**Solution**: Use `rsplit(".", 1)` to split only on the LAST dot, preserving dots in the filename:

```python
parts = i.rsplit(".", 1)
if len(parts) == 2:
    base_name = parts[0].replace(".", "_")  # Replace dots with underscores
    extension = parts[1]
    head = "img_" + escape(base_name) + "_" + escape(extension)
else:
    extension = ""
    head = "img_" + escape(i)
```

**Result**:
| Filename | rsplit(".", 1) | base_name | Manifest ID |
|----------|----------------|-----------|-------------|
| `11.9.png` | ["11.9", "png"] | "11_9" | `img_11_9_png` |
| `119.png` | ["119", "png"] | "119" | `img_119_png` |

Unique IDs - no more collisions!

## Compatibility Verified

| Pattern | Example | Before | After | Status |
|---------|---------|--------|-------|--------|
| Simple | `image.png` | `img_image_png` | `img_image_png` | Same |
| JPEG | `photo.jpg` | `img_photo_jpg` | `img_photo_jpg` | Same |
| GIF | `anim.gif` | `img_anim_gif` | `img_anim_gif` | Same |
| SVG | `icon.svg` | `img_icon_svg` | `img_icon_svg` | Same |
| **Dotted** | `11.9.png` | `img_119_png` | `img_11_9_png` | Fixed |
| Multi-dot | `fig.1.2.png` | `img_fig12_png` | `img_fig_1_2_png` | Valid |

## Files Modified
- `safaribooks_process.py`: Updated manifest ID generation in `create_content_opf()`
- `.serena/memories/session_2025-12-28_boxed_set_fixes.md`: Added documentation

## Test Book
- `9798888651889` (A Common-Sense Guide to Data Structures and Algorithms in Python, Volume 2)
- 165 chapters, 425 images, many using chapter.figure notation (e.g., `11.9.png`)

## Session Context
- Continued from `refactor-codebase` branch
- Related to previous boxed set fixes from 2025-12-28
- Analysis used Sequential MCP for systematic reasoning
