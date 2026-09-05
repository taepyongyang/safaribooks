from types import SimpleNamespace

from tests.conftest import FakeResponse


def _browser(response, active=True):
    return SimpleNamespace(active=active, fetch=lambda url, timeout=90: response)


def test_returns_none_when_browser_missing(sb):
    sb.browser = None
    assert sb.requests_provider("https://x/a") is None
    assert "not active" in sb.display.error.call_args[0][0]


def test_returns_none_when_browser_inactive(sb):
    sb.browser = _browser(FakeResponse(), active=False)
    assert sb.requests_provider("https://x/a") is None


def test_returns_none_when_fetch_fails(sb):
    sb.browser = _browser(None)
    assert sb.requests_provider("https://x/a") is None


def test_returns_response_and_records_six_tuple_last_request(sb):
    resp = FakeResponse(status_code=200, text="body", headers={"content-type": "text/html"})
    sb.browser = _browser(resp)
    out = sb.requests_provider("https://x/a")
    assert out is resp
    last = sb.display.last_request
    assert len(last) == 6
    assert last[0] == "https://x/a"
    assert last[1] is None
    assert last[2] == {}
    assert last[3] == 200
    assert "content-type: text/html" in last[4]
    assert last[5] == "body"
