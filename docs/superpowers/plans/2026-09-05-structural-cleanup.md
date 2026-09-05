# Structural Cleanup (Items 5–8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the dead credential/requests code paths, collapse HTTP to the single browser transport, consolidate configuration, and add a characterization test suite — all without changing what a successful download produces.

**Architecture:** Tests come first and act as the safety net; they pin down the pure helpers (filename fixing, link rewriting, v2→v1 reshaping, TOC generation, CSS asset parsing, expired-JWT detection) by constructing `SafariBooks` via `__new__` so the pipeline-in-constructor never runs. Only then is code removed. The riskiest change (Task 9, single response type) is isolated in its own commit and followed by a mandatory manual end-to-end download before anything else proceeds.

**Tech Stack:** Python 3.11+ (pyenv virtualenv `safaribooks`), pytest, ruff 0.12.0 (already pinned in requirements.txt).

**Spec:** None as a separate document. The scope was agreed in conversation: items 5 (dead code), 6 (single response type), 7 (config consolidation), 8 (tests) from the structural review of 2026-09-05. This plan's Goal, Global Constraints, and Ordering rationale are the spec.

## Global Constraints

- **Zero observable behavior change for a successful download.** Same files in `Books/<Title> (<ID>)/`, same EPUB filename, same `content.opf`/`toc.ncx` output, same log messages on the happy path.
- **Downloads stay sequential.** Do not introduce threads or async.
- **Browser transport is the only HTTP path.** Nothing may re-introduce a `requests.Session` for O'Reilly content.
- **`display.last_request` keeps its 6-tuple shape** `(url, data, kwargs, status_code, headers_text, body_text)` because `Display.save_last_request` formats it positionally.
- **`register_user.py` stays runnable as a standalone script** (it is legacy; do not delete it in this plan).
- **Every task ends with `ruff check .` clean and `pytest` green** before committing.
- **Manual verification gates** (after Task 9 and after Task 11) must be run by the user in an interactive terminal; a subagent cannot complete the Chrome login prompt.
- Commit after every task with the message given. Do not squash.

## Ordering rationale

1. Tests (Tasks 1–6) before any deletion, so each removal is checked against recorded behavior.
2. Dead code in the process module (Task 7) and the auth module (Task 8) next; these are pure deletions of unreachable code.
3. Single response type (Task 9) last of the code changes; it touches 10 call sites and is the one place a mistake could break a download.
4. Config consolidation (Task 10) after 9 because by then several constants have no consumers.
5. Final verification and docs (Task 11).

---

## File map

| File | Status | Responsibility after this plan |
|------|--------|-------------------------------|
| `tests/conftest.py` | create | `sb` fixture (bare `SafariBooks` with stub collaborators), `FakeResponse` |
| `tests/test_filenames.py` | create | `fix_duplicate_filenames`, `build_filename_mapping`, `generate_epub_filename`, `escape_dirname` |
| `tests/test_links.py` | create | `link_replace` |
| `tests/test_api_adapter.py` | create | `_extract_*`, `_reshape_toc_v2_to_v1`, `get_book_chapters`, `get_book_info`, `parse_toc` |
| `tests/test_css_assets.py` | create | `parse_css_for_assets`, `_validate_asset_path`, `_validate_asset_url` |
| `tests/test_get_html.py` | create | `get_html` success / truncated-JWT / 403 / transport-failure |
| `tests/test_config.py` | create | transport constants derive from config |
| `pytest.ini` | create | `testpaths`, `pythonpath` |
| `requirements.txt`, `Pipfile` | modify | add pytest |
| `safaribooks_process.py` | modify | remove credential login, `requests.Session`, `handle_cookie_update`; `requests_provider` returns `BrowserResponse | None` |
| `safaribooks_browser_auth.py` | modify | reduced to Chrome discovery/launch/CDP-ready helpers |
| `safaribooks_browser_transport.py` | modify | derive `HOME_URL`/`ORIGIN`/domain filter from config |
| `safaribooks_config.py` | modify | drop unused constants; add `CHROME_PROFILE_DIR` |
| `register_user.py` | modify | owns its own `HEADERS`, cookie regex, register URLs, proxy settings |
| `CLAUDE.md` | modify | reflect the new transport contract and the test command |

---

### Task 1: Test scaffold

**Files:**
- Create: `pytest.ini`
- Create: `tests/__init__.py` (empty)
- Create: `tests/conftest.py`
- Modify: `requirements.txt` (append one line)
- Modify: `Pipfile` (`[dev-packages]` section)

**Interfaces:**
- Produces: fixture `sb` → a `SafariBooks` instance whose `__init__` was never run, with `args`, `display` (MagicMock; `exit` raises `SystemExit`), `diagnostics` (disabled), `book_id="9781234567890"`, empty asset lists/sets, and real `BOOK_PATH`/`css_path`/`images_path` directories under `tmp_path`.
- Produces: class `FakeResponse(status_code=200, text="", json_data=None, headers=None, content=None)` with `.text`, `.content`, `.headers`, `.url`, `.json()`, `.iter_content(chunk_size)`.

- [ ] **Step 1: Add pytest as a dependency**

Append to `requirements.txt`:
```
pytest>=8.0
```
In `Pipfile`, change the empty `[dev-packages]` block to:
```
[dev-packages]
pytest = ">=8.0"
```
Install: `pip3 install pytest`

- [ ] **Step 2: Create `pytest.ini`**

```ini
[pytest]
testpaths = tests
pythonpath = .
```

- [ ] **Step 3: Create `tests/__init__.py`** (empty file) and `tests/conftest.py`:

```python
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
```

- [ ] **Step 4: Add a smoke test to prove the fixture imports and constructs**

Create `tests/test_smoke.py`:
```python
def test_fixture_builds_without_running_pipeline(sb):
    assert sb.book_id == "9781234567890"
    assert sb.debug is False
```

- [ ] **Step 5: Run it**

Run: `pytest -v`
Expected: `1 passed`. If import fails with `ModuleNotFoundError: safaribooks_process`, confirm `pythonpath = .` is in `pytest.ini` and you are running from the repo root.

- [ ] **Step 6: Lint and commit**

Run: `ruff check tests pytest.ini` → expect no findings for `tests/`.
```bash
git add pytest.ini tests/ requirements.txt Pipfile
git commit -m "test: add pytest scaffold with bare SafariBooks fixture"
```

---

### Task 2: Characterize filename helpers

**Files:**
- Create: `tests/test_filenames.py`

**Interfaces:**
- Consumes: `sb` fixture from Task 1.
- Exercises: `SafariBooks.fix_duplicate_filenames(chapters)`, `build_filename_mapping()`, `generate_epub_filename(title, authors, max_length=200)` (static), `escape_dirname(dirname, clean_space=False)` (static).

- [ ] **Step 1: Write the tests**

```python
from safaribooks_process import SafariBooks


def _ch(filename, content):
    return {"filename": filename, "content": content, "title": filename}


def test_no_duplicates_returns_unchanged(sb):
    chapters = [_ch("a.xhtml", "https://x/files/a.xhtml"), _ch("b.xhtml", "https://x/files/b.xhtml")]
    assert sb.fix_duplicate_filenames(chapters) == chapters


def test_duplicates_get_parent_dir_prefix(sb):
    chapters = [
        _ch("index.xhtml", "https://x/files/html/ch1/index.xhtml"),
        _ch("index.xhtml", "https://x/files/html/ch2/index.html"),
    ]
    out = sb.fix_duplicate_filenames(chapters)
    assert [c["filename"] for c in out] == ["ch1_index.xhtml", "ch2_index.xhtml"]


def test_boxed_set_gets_numeric_suffix(sb):
    chapters = [
        _ch("cover.xhtml", "https://x/files/book1/xhtml/cover.xhtml"),
        _ch("cover.xhtml", "https://x/files/book2/xhtml/cover.xhtml"),
        _ch("cover.xhtml", "https://x/files/book3/xhtml/cover.xhtml"),
    ]
    out = sb.fix_duplicate_filenames(chapters)
    assert [c["filename"] for c in out] == [
        "xhtml_cover.xhtml", "xhtml_cover_1.xhtml", "xhtml_cover_2.xhtml",
    ]


def test_build_filename_mapping_patterns(sb):
    sb.book_chapters = [
        {"filename": "ch1_index.xhtml", "content": "https://x/files/html/ch1/index.html"},
    ]
    sb.build_filename_mapping()
    m = sb.filename_mapping
    for key in [
        "html/ch1/index.html", "html/ch1/index.xhtml",
        "ch1/index.html", "ch1/index.xhtml",
        "index.html", "index.xhtml",
    ]:
        assert m[key] == "ch1_index.xhtml", key
    assert sb.content_url_to_filename["https://x/files/html/ch1/index.html"] == "ch1_index.xhtml"


def test_generate_epub_filename_dict_authors():
    assert SafariBooks.generate_epub_filename(
        "Core Java", [{"name": "Cay Horstmann"}]
    ) == "Core Java_Cay Horstmann.epub"


def test_generate_epub_filename_string_author_and_unsafe_chars():
    assert SafariBooks.generate_epub_filename("A: B/C?", "X|Y") == "A B C_X Y.epub"


def test_generate_epub_filename_no_authors():
    assert SafariBooks.generate_epub_filename("T", []) == "T_Unknown.epub"


def test_generate_epub_filename_truncates():
    name = SafariBooks.generate_epub_filename("x" * 300, "a", max_length=50)
    assert name.endswith(".epub")
    assert len(name) <= 50


def test_escape_dirname_replaces_unsafe_chars():
    assert SafariBooks.escape_dirname("A/B?C") == "A_B_C"


def test_escape_dirname_drops_long_subtitle_after_colon():
    assert SafariBooks.escape_dirname("A Very Long Book Title: The Subtitle") == "A Very Long Book Title"
```

- [ ] **Step 2: Run**

Run: `pytest tests/test_filenames.py -v`
Expected: `10 passed`. These are characterization tests of existing code, so they should pass on the first run. If one fails, the assertion is wrong about current behavior — read the method, fix the expected value, and note it in the commit body. Do not change production code in this task.

- [ ] **Step 3: Commit**

```bash
git add tests/test_filenames.py
git commit -m "test: characterize filename helpers"
```

---

### Task 3: Characterize `link_replace`

**Files:**
- Create: `tests/test_links.py`

**Interfaces:**
- Consumes: `sb` fixture. `link_replace` reads `self.filename_mapping`, `self.current_asset_base_url`, `self.current_api_v2_detected`, `self.book_id`, and appends to `self.images` via `_add_image`.

- [ ] **Step 1: Write the tests**

```python
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
```

- [ ] **Step 2: Run**

Run: `pytest tests/test_links.py -v`
Expected: `7 passed`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_links.py
git commit -m "test: characterize link_replace"
```

---

### Task 4: Characterize the v2 API adapter and TOC generation

**Files:**
- Create: `tests/test_api_adapter.py`

**Interfaces:**
- Consumes: `sb`, `FakeResponse`. Tests monkeypatch `sb.requests_provider` with a lambda accepting `(url, **kw)` — this signature must keep working after Task 9.
- Exercises: `_extract_filename_from_reference_id`, `_extract_href_from_reference_id`, `_reshape_toc_v2_to_v1`, `get_book_chapters`, `get_book_info`, `parse_toc`.

- [ ] **Step 1: Write the tests**

```python
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
```

- [ ] **Step 2: Run**

Run: `pytest tests/test_api_adapter.py -v`
Expected: `9 passed`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_api_adapter.py
git commit -m "test: characterize v2 adapter reshaping and TOC generation"
```

---

### Task 5: Characterize CSS asset parsing and validation

**Files:**
- Create: `tests/test_css_assets.py`

**Interfaces:**
- Consumes: `sb` (uses the real `css_path` and `BOOK_PATH` directories under `tmp_path`).
- Exercises: `parse_css_for_assets()`, `_validate_asset_path(asset_path)` → `(is_safe, resolved_path, target_dir)`, `_validate_asset_url(url)` → bool.

- [ ] **Step 1: Write the tests**

```python
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
```

- [ ] **Step 2: Run**

Run: `pytest tests/test_css_assets.py -v`
Expected: `5 passed`.

- [ ] **Step 3: Commit**

```bash
git add tests/test_css_assets.py
git commit -m "test: characterize CSS asset parsing and path/URL validation"
```

---

### Task 6: Characterize `get_html` (including expired-JWT detection)

**Files:**
- Create: `tests/test_get_html.py`

**Interfaces:**
- Consumes: `sb`, `FakeResponse`. Note the transport-failure test uses `0` here; **Task 9 changes it to `None`** (this is intentional and listed in Task 9).

- [ ] **Step 1: Write the tests**

```python
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
```

- [ ] **Step 2: Run**

Run: `pytest tests/test_get_html.py -v`
Expected: `5 passed`.

- [ ] **Step 3: Run the whole suite and commit**

Run: `pytest -q`
Expected: `37 passed` (1 smoke + 10 + 7 + 9 + 5 + 5).
```bash
git add tests/test_get_html.py
git commit -m "test: characterize get_html including expired-JWT detection"
```

---

### Task 7: Remove the dead credential-login path from `safaribooks_process.py`

**Files:**
- Modify: `safaribooks_process.py`

**Interfaces:**
- Removes: `SafariBooks.LOGIN_URL`, `parse_cred`, `do_login`, `validate_session`, `self.jwt`.
- Keeps (until Task 9): `handle_cookie_update`, `self.session`, `HEADERS`, `COOKIE_FLOAT_MAX_AGE_PATTERN`, `LOGIN_ENTRY_URL` (referenced by `HEADERS["Referer"]`).

Evidence these are dead: `grep -n "do_login\|parse_cred\|validate_session\|self.jwt" *.py` shows definitions and the single `self.jwt = {}` assignment only. `args.cred` is forced to `None` in `safaribooks_refactored.py` before `SafariBooks` is constructed.

- [ ] **Step 1: Delete the three methods**

Remove, in full, including decorators and docstrings:
- `@staticmethod` + `def parse_cred(cred):` (currently lines 456–468)
- `def do_login(self, email, password):` (currently lines 470–523)
- `def validate_session(self) -> tuple:` (currently lines 538–570)

Locate them by `grep -n "def parse_cred\|def do_login\|def validate_session" safaribooks_process.py` rather than trusting the line numbers; delete from the `def` (or its `@staticmethod` line) up to but not including the next `def` at the same indentation.

- [ ] **Step 2: Delete the class constant and instance attribute**

Remove line `LOGIN_URL = ORLY_BASE_URL + "/member/auth/login/"` from the class body.
Remove line `self.jwt = {}` from `__init__`.

- [ ] **Step 3: Let ruff find the now-unused imports**

Run: `ruff check safaribooks_process.py`
Expected findings (F401): `stat`, `quote_plus`, `PROFILE_URL`, `API_ORIGIN_URL`, `ORLY_BASE_URL`, `browser_login`. Remove each of those names from their import statements. Do **not** run `ruff --fix` blindly; edit by hand so nothing else is touched.

Run again: `ruff check safaribooks_process.py` → expect `All checks passed!`

- [ ] **Step 4: Syntax and tests**

Run: `python3 -m py_compile safaribooks_process.py && pytest -q`
Expected: compiles; `37 passed`.

- [ ] **Step 5: Commit**

```bash
git add safaribooks_process.py
git commit -m "refactor: remove dead credential-login path (do_login, parse_cred, validate_session)"
```

---

### Task 8: Prune `safaribooks_browser_auth.py` to the Chrome helpers the transport uses

**Files:**
- Modify: `safaribooks_browser_auth.py`

**Interfaces:**
- Keeps (imported by `safaribooks_browser_transport.py`): `CDP_PORT`, `CDP_TIMEOUT`, `find_chrome_path()`, `launch_chrome_with_debugging(url)`, `wait_for_cdp_ready(timeout)`.
- Removes: `OREILLY_LOGIN_URL`, `OREILLY_DOMAINS`, `get_cookies_via_cdp()`, `filter_oreilly_cookies()`, `browser_login()`, `validate_cookies()`, and the `if __name__ == "__main__":` block.

Evidence: `grep -n "get_cookies_via_cdp\|filter_oreilly_cookies\|browser_login\|validate_cookies" *.py` shows no callers outside this file after Task 7.

- [ ] **Step 1: Replace the module docstring**

```python
"""
Chrome discovery and launch helpers for the browser-routed transport.

Launches Chrome with the DevTools Protocol enabled on CDP_PORT and a throwaway
profile, and waits until the /json endpoint answers. The transport module
(`safaribooks_browser_transport.py`) does everything else over the resulting
websocket.
"""
```

- [ ] **Step 2: Delete the dead functions and constants**

Delete `OREILLY_LOGIN_URL = ...` and `OREILLY_DOMAINS = [...]` from the configuration block.
Delete, in full: `def get_cookies_via_cdp`, `def filter_oreilly_cookies`, `def browser_login`, `def validate_cookies`, and everything from `if __name__ == "__main__":` to end of file.

- [ ] **Step 3: Let ruff find unused imports**

Run: `ruff check safaribooks_browser_auth.py`
Expected F401 for some of `json`, `stat`, `os`. Remove the flagged names only. `requests` stays (used by `wait_for_cdp_ready`), as do `platform`, `subprocess`, `time`, `Path`.

- [ ] **Step 4: Verify the transport still imports and the suite passes**

Run:
```bash
python3 -c "import safaribooks_browser_transport; print('ok')"
ruff check . && pytest -q
```
Expected: `ok`, `All checks passed!`, `37 passed`.

- [ ] **Step 5: Commit**

```bash
git add safaribooks_browser_auth.py
git commit -m "refactor: reduce browser_auth to Chrome launch helpers used by the transport"
```

---

### Task 9: Single response type — `requests_provider` returns `BrowserResponse | None`

**Files:**
- Modify: `safaribooks_process.py` (imports, `__init__`, `handle_cookie_update`, `requests_provider`, 10 call sites)
- Modify: `register_user.py` (take ownership of `HEADERS`, `LOGIN_ENTRY_URL`, `COOKIE_FLOAT_MAX_AGE_PATTERN`)
- Modify: `tests/test_get_html.py` (sentinel `0` → `None`)

**Interfaces:**
- Produces: `SafariBooks.requests_provider(self, url, timeout=REQUESTS_TIMEOUT) -> BrowserResponse | None`. Returns `None` when the transport is inactive or the in-page fetch failed; never returns `0`.
- Every caller switches from `if response == 0:` to `if response is None:` and from `!= 0` to `is not None`.

Why this is safe: after Task 7 nothing calls `requests_provider` with `is_post=True`, so the `requests.Session` branch is unreachable for GETs whenever the browser is active, and the browser is always started in `__init__` (startup failure calls `display.exit`). The retry adapter and spoofed headers on the session were therefore already inert.

- [ ] **Step 1: Update the failing test first**

In `tests/test_get_html.py` change:
```python
    sb.requests_provider = lambda url, **kw: 0  # Task 9 changes this sentinel to None
```
to
```python
    sb.requests_provider = lambda url, **kw: None
```
Run: `pytest tests/test_get_html.py::test_get_html_transport_failure_returns_none -v`
Expected: **FAIL** — `get_html` currently checks `== 0`, so `None` falls through to `response.status_code` and raises `AttributeError`.

- [ ] **Step 2: Replace `requests_provider` and delete `handle_cookie_update`**

Delete `def handle_cookie_update(self, set_cookie_headers):` in full. Replace the whole `def requests_provider(...)` with:

```python
    def requests_provider(self, url, timeout=REQUESTS_TIMEOUT):
        """Fetch `url` through the logged-in browser.

        Returns a BrowserResponse, or None if the transport is not active or the
        in-page fetch() failed (the transport has already logged the error).
        fetch() follows redirects itself, so callers never see 3xx responses.
        """
        if self.browser is None or not self.browser.active:
            self.display.error("Browser transport not active; cannot fetch %s" % url)
            return None

        response = self.browser.fetch(url, timeout=timeout)
        if response is None:
            return None

        self.display.last_request = (
            url, None, {}, response.status_code,
            "\n".join("\t{}: {}".format(k, v) for k, v in response.headers.items()),
            response.text,
        )
        return response
```

- [ ] **Step 3: Remove the `requests.Session` from `__init__`**

Delete this block from `__init__` (currently right after the `DiagnosticCollector` setup and the two mapping dict initialisations):
```python
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        if USE_PROXY:  # DEBUG
            self.session.proxies = PROXIES
            self.session.verify = False

        self.session.headers.update(self.HEADERS)
```

- [ ] **Step 4: Move `HEADERS`, `LOGIN_ENTRY_URL`, and the cookie regex to `register_user.py`**

In `safaribooks_process.py` delete the class attributes `LOGIN_ENTRY_URL`, `HEADERS` (the whole dict), and `COOKIE_FLOAT_MAX_AGE_PATTERN`.

In `register_user.py`, replace the imports block with:
```python
import re

import requests

from safaribooks_config import (
    CHECK_EMAIL,
    CHECK_PWD,
    CSRF_TOKEN_RE,
    PROXIES,
    REGISTER_URL,
    SAFARI_BASE_URL,
    USE_PROXY,
)

LOGIN_ENTRY_URL = SAFARI_BASE_URL + "/login/unified/?next=/home/"

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": LOGIN_ENTRY_URL,
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "sec-ch-ua": '"Chromium";v="126", "Google Chrome";v="126", "Not.A/Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/126.0.0.0 Safari/537.36"
}

COOKIE_FLOAT_MAX_AGE_PATTERN = re.compile(r'(max-age=\d*\.\d*)', re.IGNORECASE)
```
Then in the same file replace `SafariBooks.HEADERS` with `HEADERS` and `SafariBooks.COOKIE_FLOAT_MAX_AGE_PATTERN` with `COOKIE_FLOAT_MAX_AGE_PATTERN`. Confirm with `grep -n "SafariBooks" register_user.py` → no output.

- [ ] **Step 5: Update every call site**

Run `grep -n "== 0\|!= 0" safaribooks_process.py` and change each `response == 0` to `response is None` and `search_response != 0` to `search_response is not None`. After Task 7 there are exactly these sites: `check_login`, `get_book_info` (two), `get_book_chapters`, `get_default_cover`, `get_html`, `_thread_download_css`, `_thread_download_images`, `download_css_asset`, `create_toc`.

Also remove the now-meaningless keyword arguments at call sites:
- `check_login`: `self.requests_provider(test_url, perform_redirect=False)` → `self.requests_provider(test_url)`
- `get_default_cover`, `_thread_download_css`, `_thread_download_images`, `download_css_asset`: drop `, stream=True`.

Confirm: `grep -n "stream=True\|perform_redirect" safaribooks_process.py` → no output.

- [ ] **Step 6: Remove dead imports**

Run: `ruff check safaribooks_process.py`
Expected F401 for `requests`, `HTTPAdapter`, `Retry`, `USE_PROXY`, `PROXIES`. Remove those names (delete the `from requests.adapters import HTTPAdapter` and `from urllib3.util.retry import Retry` lines entirely). Re-run until clean.

Grep to be sure nothing else referenced the session: `grep -n "self.session\|requests\." safaribooks_process.py` → no output.

- [ ] **Step 7: Verify**

Run:
```bash
python3 -m py_compile safaribooks_process.py register_user.py
ruff check .
pytest -q
```
Expected: compiles, `All checks passed!`, `37 passed` (the Step 1 test now passes).

- [ ] **Step 8: Commit**

```bash
git add safaribooks_process.py register_user.py tests/test_get_html.py
git commit -m "refactor: make browser transport the only HTTP path; requests_provider returns BrowserResponse or None"
```

- [ ] **Step 9: STOP — manual verification gate (user runs this)**

This is the one change that can break a real download. Before continuing, the user must run, in an interactive terminal:
```bash
python3 safaribooks_refactored.py --debug --preserve-log <a book ID you have downloaded before>
```
Pass criteria:
- Chrome opens, login succeeds (from cookies or manually), "Browser session ready" is printed.
- Download completes and the EPUB path is printed.
- `Books/<Title> (<ID>)/diagnostic_report_<ID>.json` shows chapters/css/images complete (compare `expected` vs `succeeded` per stage).
- `info_<ID>.log` contains no `Browser transport not active` lines.

If any criterion fails, `git revert HEAD` and report the log excerpt. Do not proceed to Task 10.

---

### Task 10: Consolidate configuration

**Files:**
- Modify: `safaribooks_config.py`
- Modify: `safaribooks_browser_transport.py`
- Modify: `safaribooks_browser_auth.py`
- Modify: `register_user.py`
- Create: `tests/test_config.py`

**Interfaces:**
- `safaribooks_config.py` after this task exports exactly: `PATH`, `COOKIES_FILE`, `CHROME_PROFILE_DIR`, `ORLY_BASE_HOST`, `SAFARI_BASE_HOST`, `API_ORIGIN_HOST`, `SAFARI_BASE_URL`.
- `register_user.py` owns `REGISTER_URL`, `CHECK_EMAIL`, `CHECK_PWD`, `CSRF_TOKEN_RE`, `USE_PROXY`, `PROXIES`.
- Transport constants `HOME_URL` and `ORIGIN` derive from `SAFARI_BASE_URL`; the domain filter uses `ORLY_BASE_HOST`. Values are byte-identical to today's literals.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:
```python
import safaribooks_config as cfg
from safaribooks_browser_transport import HOME_URL, ORIGIN
from safaribooks_browser_auth import CHROME_PROFILE_DIR


def test_transport_urls_derive_from_config():
    assert HOME_URL == "https://learning.oreilly.com/home/"
    assert ORIGIN == "https://learning.oreilly.com"
    assert HOME_URL.startswith(cfg.SAFARI_BASE_URL)


def test_chrome_profile_dir_comes_from_config():
    assert CHROME_PROFILE_DIR == cfg.CHROME_PROFILE_DIR == "/tmp/safaribooks_chrome_profile"


def test_config_has_no_legacy_constants():
    for name in ["PROFILE_URL", "API_ORIGIN_URL", "ORLY_BASE_URL",
                 "REGISTER_URL", "CHECK_EMAIL", "CHECK_PWD", "CSRF_TOKEN_RE",
                 "USE_PROXY", "PROXIES"]:
        assert not hasattr(cfg, name), name
```
Run: `pytest tests/test_config.py -v`
Expected: FAIL (`ImportError: cannot import name 'CHROME_PROFILE_DIR'`).

- [ ] **Step 2: Rewrite `safaribooks_config.py`**

```python
import os

# =====================
# Path Configuration
# =====================
PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

# Throwaway Chrome profile used by the browser transport. Kept outside the
# repo and outside the user's real Chrome profile so the two never collide.
CHROME_PROFILE_DIR = "/tmp/safaribooks_chrome_profile"

# =====================
# Host & URL Constants
# =====================
ORLY_BASE_HOST   = "oreilly.com"  # Main O'Reilly domain
SAFARI_BASE_HOST = f"learning.{ORLY_BASE_HOST}"
API_ORIGIN_HOST  = f"api.{ORLY_BASE_HOST}"

SAFARI_BASE_URL  = f"https://{SAFARI_BASE_HOST}"
```

- [ ] **Step 3: Move register-only constants into `register_user.py`**

Replace the `from safaribooks_config import (...)` block written in Task 9 with:
```python
from safaribooks_config import SAFARI_BASE_URL

# =====================
# Registration endpoints (legacy; only this script uses them)
# =====================
REGISTER_URL  = f"{SAFARI_BASE_URL}/register/"
CHECK_EMAIL   = f"{SAFARI_BASE_URL}/check-email-availability/"
CHECK_PWD     = f"{SAFARI_BASE_URL}/check-password/"
CSRF_TOKEN_RE = re.compile(r"(?<=name='csrfmiddlewaretoken' value=')([^']+)")

# Debug proxy (e.g. mitmproxy) for this script only
USE_PROXY = False
PROXIES   = {"https": "https://127.0.0.1:8080"}
```
(`import re` is already present from Task 9.)

- [ ] **Step 4: Point the transport and launcher at config**

In `safaribooks_browser_transport.py` replace:
```python
HOME_URL = "https://learning.oreilly.com/home/"
ORIGIN = "https://learning.oreilly.com"
```
with:
```python
from safaribooks_config import ORLY_BASE_HOST, SAFARI_BASE_URL

HOME_URL = SAFARI_BASE_URL + "/home/"
ORIGIN = SAFARI_BASE_URL
```
(place the import with the other local imports, above the `_FETCH_JS` constant).

In `_logged_in`, change `return "oreilly.com" in href and "/login" not in href` to `return ORLY_BASE_HOST in href and "/login" not in href`.
In `save_cookies`, change `if "oreilly.com" in c.get("domain", "")` to `if ORLY_BASE_HOST in c.get("domain", "")`.

In `safaribooks_browser_auth.py`, add `from safaribooks_config import CHROME_PROFILE_DIR` and in `launch_chrome_with_debugging` replace:
```python
    temp_profile = Path("/tmp/safaribooks_chrome_profile")
```
with:
```python
    temp_profile = Path(CHROME_PROFILE_DIR)
```

- [ ] **Step 5: Verify**

Run:
```bash
grep -rn "PROFILE_URL\|API_ORIGIN_URL\|ORLY_BASE_URL" *.py   # expect no output
ruff check . && python3 -m py_compile *.py && pytest -q
```
Expected: `All checks passed!`, compiles, `40 passed`.

- [ ] **Step 6: Commit**

```bash
git add safaribooks_config.py safaribooks_browser_transport.py safaribooks_browser_auth.py register_user.py tests/test_config.py
git commit -m "refactor: consolidate config; transport derives URLs from config, register_user owns its constants"
```

---

### Task 11: Final verification and documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `.serena/memories/architecture.md` (one line)

- [ ] **Step 1: Full static and unit verification**

```bash
ruff check .
python3 -m py_compile *.py
pytest -q
git status --short          # only intended files
```
Expected: clean, compiles, `40 passed`.

- [ ] **Step 2: STOP — manual end-to-end verification gate (user runs this)**

Same procedure as Task 9 Step 9, on the same book ID, plus one extra check: `--kindle --convert` together, to exercise the post-processing path:
```bash
python3 safaribooks_refactored.py --debug --preserve-log --kindle --convert <BOOK_ID>
```
Pass criteria as in Task 9, plus `<name>.final.epub` is produced by the Calibre round-trip. Optionally diff `OEBPS/content.opf` and `OEBPS/toc.ncx` against a copy of the same book downloaded before this branch: they must be identical.

- [ ] **Step 3: Update `CLAUDE.md`**

In the `## Development Commands` code block add, after the ruff line:
```bash
pytest                    # characterization tests for the pure helpers (no network)
```
Replace the sentence starting "No automated tests exist." with:
> Unit tests in `tests/` cover the pure helpers (filename fixing, link rewriting, v2→v1 reshaping, TOC, CSS asset parsing, expired-JWT detection) by constructing `SafariBooks` via `__new__` with stub collaborators — see `tests/conftest.py`. They do not cover the browser transport or EPUB packaging; those are verified manually: download a book with `--debug`, read the diagnostic report, then open the EPUB in Calibre.

In `### Browser transport`, replace the first bullet with:
> - `requests_provider()` routes **every request** through `BrowserTransport.fetch()` and returns a `BrowserResponse` (`status_code`, `text`, `content`, `headers`, `json()`, `iter_content()`) or `None` on transport failure. There is no `requests.Session` fallback any more; callers check `is None`.

In the file map, change the `safaribooks_browser_auth.py` line to `Chrome discovery/launch helpers (find_chrome_path, launch, wait for CDP)` and the `safaribooks_config.py` line to `Paths, hosts, SAFARI_BASE_URL, CHROME_PROFILE_DIR`.

- [ ] **Step 4: Update the Serena architecture memory**

In `.serena/memories/architecture.md`, under `### safaribooks_process.py`, replace the line `- Authentication: \`do_login()\`, \`check_login()\`, \`parse_cred()\`` with `- Authentication: \`check_login()\` (v2 search probe through the browser transport)` and replace `- Session management: \`requests_provider()\`, \`handle_cookie_update()\`` with `- HTTP: \`requests_provider()\` → BrowserResponse or None`.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md .serena/memories/architecture.md
git commit -m "docs: document test suite and single-transport HTTP contract"
```

---

## Self-review

**Scope coverage.** Item 5 (dead code) → Tasks 7, 8, and the session/`handle_cookie_update` removal in 9. Item 6 (single response type) → Task 9. Item 7 (config) → Task 10. Item 8 (tests) → Tasks 1–6 plus `test_config.py` in 10. Every task ends with ruff + pytest; manual gates sit after the risky task and at the end.

**Placeholders.** None: every step has the code or the exact grep/edit instruction.

**Type consistency.** `requests_provider(self, url, timeout=REQUESTS_TIMEOUT)` in Task 9 matches the `lambda url, **kw` monkeypatches in Tasks 4 and 6 (extra kwargs are simply never passed). `FakeResponse` exposes the same attribute set as `BrowserResponse`. `CHROME_PROFILE_DIR` is defined in config (Task 10 Step 2) before being imported by `browser_auth` (Step 4) and asserted in the test (Step 1). Test count arithmetic: 1 + 10 + 7 + 9 + 5 + 5 = 37 after Task 6; +3 in Task 10 = 40.

**Deliberately out of scope.** Deleting `register_user.py`, renaming `safaribooks_browser_auth.py`, restricting `--remote-allow-origins`, and any change to `Display` or the constructor-runs-pipeline shape (items 1–4 of the review).
