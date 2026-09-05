from safaribooks_process import SafariBooks
from tests.conftest import FakeResponse

FILES = "https://learning.oreilly.com/api/v2/epubs/urn:orm:book:9781234567890/files"


def test_extract_filename_from_reference_id():
    assert SafariBooks._extract_filename_from_reference_id("9781633437333-/Text/preface.html") == "preface.html"
    assert SafariBooks._extract_filename_from_reference_id("") == "unknown.html"


def test_extract_href_from_reference_id():
    assert SafariBooks._extract_href_from_reference_id("9781633437333-/Text/preface.html") == "Text/preface.html"
    assert SafariBooks._extract_href_from_reference_id("plain/thing.html") == "thing.html"


def test_reshape_toc_v2_to_v1(sb):
    v2 = [{
        "reference_id": "978-/Text/ch1.html", "title": "One", "depth": 1, "fragment": "",
        "children": [{
            "reference_id": "978-/Text/ch1.html", "title": "Sub", "depth": 2, "fragment": "s1",
            "children": [],
        }],
    }]
    out = sb._reshape_toc_v2_to_v1(v2)
    assert out[0]["href"] == "Text/ch1.html"
    assert out[0]["label"] == "One"
    assert out[0]["id"] == "978__Text_ch1.html"
    assert out[0]["children"][0]["fragment"] == "s1"


def test_get_book_chapters_reshapes_and_moves_cover_first(sb):
    page = {"count": 2, "next": None, "results": [
        {
            "reference_id": "978-/Text/ch1.html", "title": "Chapter 1",
            "content_url": "https://x/files/Text/ch1.html",
            "related_assets": {
                "images": [FILES + "/Images/a.png", "https://cdn/other.png"],
                "stylesheets": ["https://x/s.css"],
            },
        },
        {
            "reference_id": "978-/Text/cover.html", "title": "Cover",
            "content_url": "https://x/files/Text/cover.html",
            "related_assets": {},
        },
    ]}
    sb.requests_provider = lambda url, **kw: FakeResponse(json_data=page)
    chapters = sb.get_book_chapters()
    assert [c["filename"] for c in chapters] == ["cover.html", "ch1.html"]
    ch1 = chapters[1]
    assert ch1["content"] == "https://x/files/Text/ch1.html"
    assert ch1["images"] == ["Images/a.png", "https://cdn/other.png"]
    assert ch1["stylesheets"] == [{"url": "https://x/s.css"}]
    assert ch1["asset_base_url"] == FILES
    assert ch1["site_styles"] == []


def test_get_book_chapters_follows_pagination(sb):
    pages = {
        0: {"count": 2, "next": "more", "results": [
            {"reference_id": "978-/a.html", "title": "A", "content_url": "u", "related_assets": {}}]},
        1: {"count": 2, "next": None, "results": [
            {"reference_id": "978-/b.html", "title": "B", "content_url": "u", "related_assets": {}}]},
    }
    sb.requests_provider = lambda url, **kw: FakeResponse(
        json_data=pages[int(url.rsplit("offset=", 1)[1])]
    )
    assert [c["filename"] for c in sb.get_book_chapters()] == ["a.html", "b.html"]


def test_get_book_info_reshape(sb):
    epub = {
        "title": "T", "isbn": "111", "identifier": "urn",
        "descriptions": {"text/plain": "d"}, "publication_date": "2020-01-01", "language": None,
    }
    search = {"results": [{
        "authors": ["A"], "publishers": ["P"], "web_url": "https://w", "cover_url": "https://c.png",
    }]}
    sb.requests_provider = lambda url, **kw: FakeResponse(json_data=search if "search" in url else epub)
    info = sb.get_book_info()
    assert info["title"] == "T"
    assert info["isbn"] == "111"
    assert info["description"] == "d"
    assert info["authors"] == [{"name": "A"}]
    assert info["publishers"] == [{"name": "P"}]
    assert info["cover"] == "https://c.png"
    assert info["language"] == "en-US"
    assert info["rights"] == ""


def test_get_book_info_omits_cover_when_missing(sb):
    epub = {"title": "T", "descriptions": {}}
    sb.requests_provider = lambda url, **kw: FakeResponse(
        json_data={"results": [{}]} if "search" in url else epub
    )
    info = sb.get_book_info()
    assert "cover" not in info
    assert info["web_url"].endswith("/library/view/-/9781234567890/")


def test_parse_toc_resolves_mapping_and_anchors():
    toc = [{
        "depth": 1, "href": "Text/ch1.html", "fragment": "", "id": "id1", "label": "A & B",
        "children": [{
            "depth": 2, "href": "Text/ch1.html#s1", "fragment": "s1", "id": "id2", "label": "Sub",
            "children": [],
        }],
    }]
    navmap, count, depth = SafariBooks.parse_toc(toc, {"Text/ch1.xhtml": "ch1_index.xhtml"})
    assert count == 2
    assert depth == 2
    assert '<navPoint id="id1" playOrder="1">' in navmap
    assert '<content src="ch1_index.xhtml"/>' in navmap
    assert '<navPoint id="s1" playOrder="2">' in navmap
    assert '<content src="ch1_index.xhtml#s1"/>' in navmap
    assert "A &amp; B" in navmap
