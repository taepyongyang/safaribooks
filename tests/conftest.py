import json
import os
import types
from unittest.mock import MagicMock

import pytest

from safaribooks_diagnostics import DiagnosticCollector
from safaribooks_process import SafariBooks

BOOK_ID = "9781234567890"


class FakeResponse:
    """Stand-in for BrowserResponse / requests.Response in tests."""

    def __init__(self, status_code=200, text="", json_data=None, headers=None, content=None):
        self.status_code = status_code
        self._json = json_data
        if text:
            self.text = text
        elif json_data is not None:
            self.text = json.dumps(json_data)
        else:
            self.text = ""
        self.content = content if content is not None else self.text.encode("utf-8")
        self.headers = headers or {}
        self.url = ""

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json

    def iter_content(self, chunk_size=1024):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]


@pytest.fixture
def sb(tmp_path):
    """A SafariBooks object with __init__ bypassed and collaborators stubbed."""
    obj = SafariBooks.__new__(SafariBooks)
    obj.args = types.SimpleNamespace(debug=False, kindle=False, no_cookies=False, log=False)
    obj.display = MagicMock()
    obj.display.exit.side_effect = SystemExit(1)
    obj.diagnostics = DiagnosticCollector(enabled=False, book_id=BOOK_ID)
    obj.book_id = BOOK_ID
    obj.book_chapters = []
    obj.filename_mapping = {}
    obj.content_url_to_filename = {}
    obj.css = []
    obj._css_index = {}
    obj.images = []
    obj._image_urls = set()
    obj._image_basenames = set()
    obj.css_asset_paths = []
    obj.filename = ""
    obj.chapter_title = ""
    obj.BOOK_PATH = str(tmp_path / "book")
    obj.css_path = os.path.join(obj.BOOK_PATH, "OEBPS", "Styles")
    obj.images_path = os.path.join(obj.BOOK_PATH, "OEBPS", "Images")
    os.makedirs(obj.css_path)
    os.makedirs(obj.images_path)
    obj.browser = None
    return obj
