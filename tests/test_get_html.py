import pytest

from tests.conftest import FakeResponse

FULL_PAGE = (
    "<html><body><div id='sbo-rt-content'>" + ("x" * 4000) + "</div></body></html>"
)


def test_get_html_returns_root_for_full_page(sb):
    sb.requests_provider = lambda url, **kw: FakeResponse(text=FULL_PAGE)
    root = sb.get_html("https://x/ch1.html")
    assert root is not None
    assert root.xpath("//div[@id='sbo-rt-content']")


def test_get_html_detects_truncated_jwt_preview(sb):
    sb.requests_provider = lambda url, **kw: FakeResponse(text="<html><body>preview</body></html>")
    assert sb.get_html("https://x/ch1.html") is None
    assert "expired JWT" in sb.display.error.call_args[0][0]


def test_get_html_auth_error_is_fatal(sb):
    sb.requests_provider = lambda url, **kw: FakeResponse(status_code=403, text="Access Denied")
    with pytest.raises(SystemExit):
        sb.get_html("https://x/ch1.html")


def test_get_html_other_http_error_is_skipped(sb):
    sb.requests_provider = lambda url, **kw: FakeResponse(status_code=500, text="boom")
    assert sb.get_html("https://x/ch1.html") is None


def test_get_html_transport_failure_returns_none(sb):
    sb.requests_provider = lambda url, **kw: 0  # Task 9 changes this sentinel to None
    assert sb.get_html("https://x/ch1.html") is None
