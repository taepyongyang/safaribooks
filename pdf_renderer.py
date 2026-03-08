"""
PDF Renderer

Renders downloaded EPUB assets (HTML + CSS + fonts + images) into a proper PDF
using headless Chromium via Playwright. Designed for books that were originally
PDFs converted to HTML (pdf2htmlEX style) where text is absolutely positioned
over background images — common for scanned books, manga, art books, and
technical publications with complex layouts.

These books render poorly as reflowable EPUBs but perfectly in a browser engine.
This module renders each chapter locally (no network requests) and merges the
output into a single PDF.

Requirements:
    pip install playwright pypdf
    playwright install chromium
"""

import os
import re
import shutil
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET
from lxml import html as lhtml

from safaribooks_display import C_BOLD, C_CYAN, C_DIM, C_GREEN, C_RED, C_RESET, C_YELLOW


# Regex to match the injected <style> block that breaks absolute positioning.
# This is the block added by save_page_html() via BASE_HTML template.
# We use string replacement instead of DOM parsing to preserve the original
# XHTML byte-for-byte (lxml.html would break self-closing XML tags).
OVERRIDE_STYLE_RE = re.compile(
    r'<style\s+type="text/css">[^<]*#sbo-rt-content[^<]*</style>',
    re.DOTALL
)

# CSS injected into the cleaned XHTML to ensure proper PDF pagination.
# Resets body margin (browser default 8px would push content out) and
# forces clean page breaks on each manga page div.
PDF_RENDER_CSS = (
    '<style type="text/css">'
    'body { margin: 0 !important; padding: 0 !important; }'
    '#sbo-rt-content, #pdf-main { margin: 0; padding: 0; }'
    '.pdf-page { page-break-after: always; page-break-inside: avoid; }'
    '</style>'
)


def _emit(display, msg):
    """Output a message via Display if available, otherwise print."""
    if display:
        display.out(msg)
    else:
        print(msg)


def is_converted_pdf(oebps_dir):
    """Detect if the book content was converted from PDF via pdf2htmlEX.

    Checks Style00.css for the distinctive combination of #pdf-main container
    and absolutely positioned page frames (.pf), text (.t), and images (.bi)
    that pdf2htmlEX generates. Normal reflowable books never have these.
    """
    style_path = os.path.join(oebps_dir, "Styles", "Style00.css")
    if not os.path.isfile(style_path):
        return False
    try:
        with open(style_path, 'r', encoding='utf-8') as f:
            css = f.read()
        markers = ['#pdf-main', '.pf{position:relative', '.t{position:absolute']
        return all(m in css.replace(' ', '') for m in markers)
    except (OSError, UnicodeDecodeError):
        return False


def get_spine_order(oebps_dir):
    """Parse content.opf and return XHTML file paths in reading order."""
    opf_path = os.path.join(oebps_dir, "content.opf")
    tree = ET.parse(opf_path)
    root = tree.getroot()

    # Handle OPF namespace
    default_ns = root.tag.split("}")[0] + "}" if "}" in root.tag else ""

    # Build id-to-href mapping from manifest
    id_to_href = {}
    for item in root.iter(f"{default_ns}item"):
        item_id = item.get("id")
        href = item.get("href")
        if item_id and href:
            id_to_href[item_id] = href

    # Get spine order, skipping the generated cover page (low-res EPUB thumbnail).
    # The actual book cover is already the first pdf2htmlEX page.
    spine_files = []
    for itemref in root.iter(f"{default_ns}itemref"):
        idref = itemref.get("idref")
        if idref and idref in id_to_href:
            href = id_to_href[idref]
            if href.endswith(".xhtml") and not href.startswith("default_cover"):
                full_path = os.path.join(oebps_dir, href)
                if os.path.isfile(full_path):
                    spine_files.append(full_path)

    return spine_files


def strip_epub_overrides(xhtml_path):
    """Remove the injected <style> block that breaks absolute positioning.

    Returns cleaned XHTML as a string. Uses regex on the raw file content
    to preserve the original XHTML structure (self-closing tags, namespaces).
    The injected block contains '#sbo-rt-content' rules like text-indent:0pt,
    word-break:break-word that override the pdf2htmlEX positioning CSS.
    """
    with open(xhtml_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove the injected overrides
    content = OVERRIDE_STYLE_RE.sub('', content)

    # Inject our own CSS for proper PDF pagination
    content = content.replace('</head>', PDF_RENDER_CSS + '</head>', 1)

    return content


def convert_to_pdf(oebps_dir, output_pdf, display=None, metadata=None):
    """Render all XHTML chapters to a single PDF via headless Chromium.

    Args:
        oebps_dir: Path to the OEBPS directory containing chapters, CSS, fonts, images.
        output_pdf: Output PDF file path.
        display: Optional Display instance for progress output.
        metadata: Optional dict with 'title' and 'author' keys for PDF metadata.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _emit(display, f" {C_YELLOW}⚠{C_RESET}  PDF rendering requires playwright. Install with:\n"
              "    pip install playwright && playwright install chromium")
        return False

    try:
        from pypdf import PdfWriter
    except ImportError:
        _emit(display, f" {C_YELLOW}⚠{C_RESET}  PDF merging requires pypdf. Install with:\n"
              "    pip install pypdf")
        return False

    spine_files = get_spine_order(oebps_dir)
    if not spine_files:
        _emit(display, f" {C_RED}✗{C_RESET}  No XHTML files found in spine order")
        return False

    total = len(spine_files)
    _emit(display, f"\n{C_DIM}{'━' * 40}{C_RESET}\n"
          f" {C_BOLD}{C_CYAN}▶{C_RESET}  {C_BOLD}Rendering {total} chapters via headless Chromium...{C_RESET}")

    page_width, page_height, page_unit = _detect_page_dimensions(oebps_dir)

    temp_dir = tempfile.mkdtemp(prefix="safaribooks_pdf_")
    chapter_pdfs = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()

            for i, xhtml_path in enumerate(spine_files):
                chapter_name = os.path.basename(xhtml_path)
                progress = f"[{i + 1}/{total}]"
                temp_xhtml = os.path.join(
                    os.path.dirname(xhtml_path),
                    f"_pdf_render_{chapter_name}"
                )

                try:
                    cleaned_html = strip_epub_overrides(xhtml_path)

                    with open(temp_xhtml, 'w', encoding='utf-8') as f:
                        f.write(cleaned_html)

                    file_url = Path(temp_xhtml).resolve().as_uri()
                    page.goto(file_url, wait_until='networkidle')
                    page.evaluate("() => document.fonts.ready")

                    pdf_path = os.path.join(temp_dir, f"chapter_{i:04d}.pdf")
                    page.pdf(
                        path=pdf_path,
                        width=f'{page_width}{page_unit}',
                        height=f'{page_height}{page_unit}',
                        margin={'top': '0', 'right': '0', 'bottom': '0', 'left': '0'},
                        print_background=True,
                        scale=1,
                    )
                    chapter_pdfs.append(pdf_path)
                    _emit(display, f"  {C_DIM}{progress}{C_RESET} {C_GREEN}✓{C_RESET} {chapter_name}")

                except Exception as e:
                    _emit(display, f"  {C_DIM}{progress}{C_RESET} {C_RED}✗{C_RESET} {chapter_name} — {e}")

                finally:
                    if os.path.exists(temp_xhtml):
                        os.remove(temp_xhtml)

            page.close()
            browser.close()

        if not chapter_pdfs:
            _emit(display, f" {C_RED}✗{C_RESET}  No chapters were rendered successfully")
            return False

        _emit(display, f" {C_CYAN}›{C_RESET}  Merging {len(chapter_pdfs)} chapter PDFs...")

        writer = PdfWriter()
        for pdf_path in chapter_pdfs:
            writer.append(pdf_path)

        if metadata:
            pdf_metadata = {}
            if metadata.get("title"):
                pdf_metadata["/Title"] = metadata["title"]
            if metadata.get("author"):
                pdf_metadata["/Author"] = metadata["author"]
            if pdf_metadata:
                writer.add_metadata(pdf_metadata)

        with open(output_pdf, 'wb') as f:
            writer.write(f)
        writer.close()

        _emit(display, f" {C_GREEN}{C_BOLD}✓{C_RESET}  PDF created: {output_pdf}")
        return True

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _find_css_dimension(css_content, class_name, unit):
    """Extract a dimension value for a CSS class and unit.

    Searches for patterns like '.w0 { width: 612pt' or '.h0 { height: 792px'.
    Returns the numeric value as a float, or None if not found.
    """
    property_name = "width" if class_name.startswith("w") else "height"
    match = re.search(
        rf'\.{class_name}\s*\{{\s*{property_name}:\s*(\d+(?:\.\d+)?)\s*{unit}',
        css_content
    )
    if match:
        return float(match.group(1))
    return None


def _detect_page_dimensions(oebps_dir):
    """Detect page dimensions from the CSS.

    Since page.pdf() triggers print mode, we prefer @media print dimensions
    (in pt) which match the print CSS layout. Falls back to screen CSS (px),
    then to image dimensions from HTML.

    Returns (width, height, unit) where unit is 'in' or 'px'.
    """
    styles_dir = os.path.join(oebps_dir, "Styles")

    width_pt = None
    height_pt = None
    width_px = None
    height_px = None

    if os.path.isdir(styles_dir):
        for css_file in sorted(os.listdir(styles_dir)):
            if not css_file.endswith('.css'):
                continue
            try:
                css_path = os.path.join(styles_dir, css_file)
                with open(css_path, 'r', encoding='utf-8') as f:
                    css_content = f.read()

                if width_pt is None:
                    width_pt = _find_css_dimension(css_content, "w0", "pt")
                if height_pt is None:
                    height_pt = _find_css_dimension(css_content, "h0", "pt")
                if width_px is None:
                    width_px = _find_css_dimension(css_content, "w0", "px")
                if height_px is None:
                    height_px = _find_css_dimension(css_content, "h0", "px")

            except (OSError, UnicodeDecodeError):
                continue

    # Prefer print dimensions (pt) since page.pdf() uses print mode.
    # Playwright doesn't accept 'pt' units, so convert to inches (1pt = 1/72in).
    if width_pt and height_pt:
        return (round(width_pt / 72, 4), round(height_pt / 72, 4), 'in')

    if width_px and height_px:
        return (int(width_px), int(height_px), 'px')

    # Last resort: check first XHTML for image dimensions
    for xhtml_file in sorted(os.listdir(oebps_dir)):
        if not xhtml_file.endswith('.xhtml'):
            continue
        try:
            xhtml_path = os.path.join(oebps_dir, xhtml_file)
            tree = lhtml.parse(xhtml_path)
            for img in tree.xpath('//img[contains(@class, "bi")]'):
                w = img.get('width')
                h = img.get('height')
                if w and h:
                    return (int(w), int(h), 'px')
        except Exception:
            continue

    return (1008, 1332, 'px')
