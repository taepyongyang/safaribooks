import os

from tests.conftest import FakeResponse


def _cover_response(headers):
    return FakeResponse(status_code=200, content=b"\xff\xd8jpegbytes", headers=headers)


def test_default_cover_uses_lowercase_content_type_from_browser(sb):
    sb.book_info = {"cover": "https://learning.oreilly.com/library/cover/9781234567890/"}
    sb.requests_provider = lambda url, **kw: _cover_response({"content-type": "image/jpeg"})
    assert sb.get_default_cover() == "default_cover.jpeg"
    with open(os.path.join(sb.images_path, "default_cover.jpeg"), "rb") as f:
        assert f.read() == b"\xff\xd8jpegbytes"


def test_default_cover_accepts_capitalised_content_type(sb):
    sb.book_info = {"cover": "https://x/cover"}
    sb.requests_provider = lambda url, **kw: _cover_response({"Content-Type": "image/png"})
    assert sb.get_default_cover() == "default_cover.png"


def test_default_cover_falls_back_to_jpeg_when_header_missing(sb):
    sb.book_info = {"cover": "https://x/cover"}
    sb.requests_provider = lambda url, **kw: _cover_response({})
    assert sb.get_default_cover() == "default_cover.jpeg"


def test_default_cover_returns_false_on_transport_failure(sb):
    sb.book_info = {"cover": "https://x/cover"}
    sb.requests_provider = lambda url, **kw: None
    assert sb.get_default_cover() is False
    assert "retrieve the cover" in sb.display.error.call_args[0][0]
