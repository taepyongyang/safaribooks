import os
from pathlib import Path


def test_parse_css_for_assets_filters_and_dedups(sb):
    css = (
        'a{background:url("data:image/png;base64,xx")}'
        'b{src:url(fonts/a.ttf)}'
        "c{src:url('../Misc/b.woff2')}"
        'd{@import url(other.css)}'
        'e{background:url(https://cdn/x.png)}'
        'f{src:url(fonts/a.ttf)}'
    )
    (Path(sb.css_path) / "Style00.css").write_text(css)
    (Path(sb.css_path) / "note.txt").write_text("url(ignored.ttf)")
    assert sb.parse_css_for_assets() == {
        "fonts/a.ttf": "fonts/a.ttf",
        "../Misc/b.woff2": "../Misc/b.woff2",
    }


def test_validate_asset_path_allows_sibling_dir(sb):
    ok, rel, target = sb._validate_asset_path("../Misc/font.woff2")
    assert ok is True
    assert rel == "Misc/font.woff2"
    assert target == os.path.abspath(os.path.join(sb.BOOK_PATH, "OEBPS", "Misc"))


def test_validate_asset_path_keeps_fonts_under_styles(sb):
    ok, rel, target = sb._validate_asset_path("fonts/a.ttf")
    assert ok is True
    assert rel == os.path.join("Styles", "fonts", "a.ttf")


def test_validate_asset_path_rejects_escape(sb):
    ok, rel, target = sb._validate_asset_path("../../../../etc/passwd")
    assert ok is False
    assert rel is None


def test_validate_asset_url_allows_oreilly_hosts_only(sb):
    assert sb._validate_asset_url("https://learning.oreilly.com/x.ttf") is True
    assert sb._validate_asset_url("https://cdn.oreilly.com/x.ttf") is True
    assert sb._validate_asset_url("https://evil.com/oreilly.com/x.ttf") is False
    assert sb._validate_asset_url("not a url") is False
