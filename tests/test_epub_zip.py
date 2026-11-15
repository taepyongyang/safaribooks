import os
import zipfile


def test_epub_holds_only_book_files(sb):
    oebps = os.path.join(sb.BOOK_PATH, "OEBPS")
    with open(os.path.join(oebps, "ch01.xhtml"), "w") as f:
        f.write("<html/>")
    for junk in ("Old_Book.epub", "Old_Book.final.epub", "Old_Book.pdf", "diagnostic_report_1.json"):
        with open(os.path.join(sb.BOOK_PATH, junk), "w") as f:
            f.write("old")
    sb.epub_filename = "Old_Book.epub"
    sb.create_content_opf = lambda: "<package/>"
    sb.create_toc = lambda: "<ncx/>"

    sb.create_epub()

    with zipfile.ZipFile(os.path.join(sb.BOOK_PATH, "Old_Book.epub")) as z:
        infos = z.infolist()
        names = z.namelist()
    assert names[0] == "mimetype"
    assert infos[0].compress_type == zipfile.ZIP_STORED
    assert {n.split("/")[0] for n in names} == {"mimetype", "META-INF", "OEBPS"}
    assert "OEBPS/ch01.xhtml" in names
    assert "META-INF/container.xml" in names
