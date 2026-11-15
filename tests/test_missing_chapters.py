import os
import re

from safaribooks_process import SafariBooks


def _chapters(sb, names_on_disk, names_in_list):
    for name in names_on_disk:
        with open(os.path.join(sb.BOOK_PATH, "OEBPS", name), "w") as f:
            f.write("<html/>")
    sb.cover = False
    sb.book_title = "T"
    sb.book_info = {}
    sb.book_chapters = [{"filename": n, "title": n} for n in names_in_list]
    return sb.create_content_opf()


def test_missing_chapter_not_in_manifest_or_spine(sb):
    opf = _chapters(sb, ["ch01.xhtml", "ch03.xhtml"], ["ch01.html", "ch02.html", "ch03.html"])
    assert 'href="ch02.xhtml"' not in opf
    assert 'idref="ch02"' not in opf
    assert re.findall(r'idref="(ch\d+)"', opf) == ["ch01", "ch03"]


def test_guide_points_to_first_existing_chapter(sb):
    opf = _chapters(sb, ["ch02.xhtml"], ["ch01.html", "ch02.html"])
    assert '<reference href="ch02.xhtml"' in opf


def test_toc_drops_missing_entry_and_keeps_children():
    toc = [{"depth": 1, "href": "ch1.html", "fragment": "", "id": "a", "label": "One",
            "children": [{"depth": 2, "href": "ch2.html", "fragment": "", "id": "b",
                          "label": "Two", "children": []}]}]
    navmap, count, _ = SafariBooks.parse_toc(toc, {}, existing={"ch2.xhtml"})
    assert "ch1.xhtml" not in navmap
    assert '<content src="ch2.xhtml"/>' in navmap
    assert count == 1
    assert navmap.count("<navPoint") == navmap.count("</navPoint>") == 1
