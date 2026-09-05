import pytest

FILES = "https://learning.oreilly.com/api/v2/epubs/urn:orm:book:9781234567890/files"


@pytest.fixture
def linker(sb):
    sb.filename_mapping = {
        "ch1/index.xhtml": "ch1_index.xhtml",
        "index.xhtml": "ch1_index.xhtml",
        "ch02.xhtml": "ch02.xhtml",
    }
    sb.current_asset_base_url = FILES
    sb.current_api_v2_detected = True
    return sb


def test_mailto_and_absolute_external_untouched(linker):
    assert linker.link_replace("mailto:a@b.c") == "mailto:a@b.c"
    assert linker.link_replace("https://example.com/x.html") == "https://example.com/x.html"


def test_absolute_link_containing_book_id_is_relativised(linker):
    url = "https://learning.oreilly.com/library/view/x/9781234567890/ch02.html"
    assert linker.link_replace(url) == "ch02.xhtml"


def test_image_link_rewritten_and_queued(linker):
    assert linker.link_replace("../images/fig1.png") == "Images/fig1.png"
    assert linker.images == [FILES + "/../images/fig1.png"]


def test_image_dedup_by_basename(linker):
    linker.link_replace("images/fig1.png")
    linker.link_replace("graphics/fig1.png")
    assert len(linker.images) == 1


def test_chapter_link_with_anchor_uses_mapping(linker):
    assert linker.link_replace("../ch1/index.html#sec2") == "ch1_index.xhtml#sec2"


def test_unknown_chapter_link_falls_back_to_xhtml(linker):
    assert linker.link_replace("appendix.html") == "appendix.xhtml"


def test_cover_xhtml_is_not_treated_as_image(linker):
    assert linker.link_replace("cover.xhtml") == "cover.xhtml"
    assert linker.images == []
