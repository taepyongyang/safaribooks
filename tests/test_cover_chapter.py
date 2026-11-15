import pytest

from safaribooks_process import SafariBooks


@pytest.mark.parametrize("filename", [
    "cover.xhtml", "Cover.xhtml", "00-Cover.xhtml", "01_Cover.xhtml",
    "00_cover.xhtml", "frontcover.xhtml", "9781234567890cover.xhtml", "cover.html",
])
def test_cover_file_names_match(filename):
    assert SafariBooks._is_cover_chapter(filename, "Chapter")


@pytest.mark.parametrize("filename,title", [
    ("about-the-cover-illustration.xhtml", "About the cover illustration"),
    ("18_backcover.xhtml", "Back Cover"),
    ("ch03.xhtml", "Discovering APIs"),
    ("ch09.xhtml", "Recovery"),
    ("ch10.xhtml", "Test Coverage"),
])
def test_non_cover_chapters_do_not_match(filename, title):
    assert not SafariBooks._is_cover_chapter(filename, title)


@pytest.mark.parametrize("title", ["Cover", " cover ", "Front Cover"])
def test_cover_titles_match(title):
    assert SafariBooks._is_cover_chapter("part0000.html", title)
