import os
from collections import deque

CSS = "https://learning.oreilly.com/api/v2/epubs/urn:orm:book:9781234567890/files/Styles/a.css"


def test_cached_chapter_still_numbers_its_css(sb):
    with open(os.path.join(sb.BOOK_PATH, "OEBPS", "ch01.xhtml"), "w") as f:
        f.write("<html/>")
    chapter = {"title": "One", "filename": "ch01.html", "content": "https://x/api/v2/ch01.html",
               "asset_base_url": "https://x/files", "images": [],
               "stylesheets": [{"url": CSS}], "site_styles": []}
    sb.book_chapters = [chapter]
    sb.chapters_queue = deque([chapter])
    sb.display.book_ad_info = True

    sb.get()

    assert sb.css == [CSS]
    assert sb._css_index == {CSS: 0}
