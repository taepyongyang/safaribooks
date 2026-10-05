import os
from queue import Queue

from tests.conftest import FakeResponse

NOT_FOUND = b'{"detail":"No EpubFile matches the given query."}'
BASE = "https://learning.oreilly.com/api/v2/epubs/urn:orm:book:9781234567890/files/"


def _provider(status_code, content):
    return lambda url, **kw: FakeResponse(status_code=status_code, content=content)


def test_image_404_is_not_saved(sb):
    sb.images_done_queue = Queue()
    sb.requests_provider = _provider(404, NOT_FOUND)
    sb._thread_download_images(BASE + "Images/modules.svg")
    assert not os.path.exists(os.path.join(sb.images_path, "modules.svg"))
    assert "HTTP 404" in sb.display.error.call_args[0][0]
    assert sb.images_done_queue.qsize() == 1


def test_image_200_is_saved(sb):
    sb.images_done_queue = Queue()
    sb.requests_provider = _provider(200, b"\x89PNG")
    sb._thread_download_images(BASE + "Images/fig1.png")
    with open(os.path.join(sb.images_path, "fig1.png"), "rb") as f:
        assert f.read() == b"\x89PNG"


def test_css_404_is_not_saved(sb):
    url = BASE + "Styles/main.css"
    sb.css = [url]
    sb._css_index = {url: 0}
    sb.css_done_queue = Queue()
    sb.requests_provider = _provider(404, NOT_FOUND)
    sb._thread_download_css(url)
    assert not os.path.exists(os.path.join(sb.css_path, "Style00.css"))
    assert "HTTP 404" in sb.display.error.call_args[0][0]
    assert sb.css_done_queue.qsize() == 1


def test_css_asset_404_is_not_saved(sb):
    sb.requests_provider = _provider(404, NOT_FOUND)
    assert sb.download_css_asset("fonts/x.ttf", BASE + "Styles/main.css") == (False, None)
    assert not os.path.exists(os.path.join(sb.css_path, "fonts", "x.ttf"))


def test_default_cover_404_returns_false(sb):
    sb.book_info = {"cover": "https://x/cover"}
    sb.requests_provider = lambda url, **kw: FakeResponse(
        status_code=404, content=NOT_FOUND, headers={"content-type": "application/json"})
    assert sb.get_default_cover() is False
    assert os.listdir(sb.images_path) == []
