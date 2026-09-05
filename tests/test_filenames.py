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
