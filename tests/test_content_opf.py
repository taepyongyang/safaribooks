import os
import re


def _write_image(sb, name):
    with open(os.path.join(sb.images_path, name), "wb") as f:
        f.write(b"x")


def _opf(sb, images, cover):
    for name in images:
        _write_image(sb, name)
    sb.cover = cover
    sb.book_title = "Test Book"
    sb.book_info = {}
    sb.book_chapters = [{"filename": "ch01.html", "title": "Chapter 1"}]
    return sb.create_content_opf()


def _manifest_items(opf):
    return dict(re.findall(r'<item id="([^"]+)" href="Images/[^"]+" media-type="([^"]+)"', opf))


def test_svg_image_gets_svg_xml_media_type(sb):
    items = _manifest_items(_opf(sb, ["figure.svg"], False))
    assert items["img_figure_svg"] == "image/svg+xml"


def test_common_image_media_types(sb):
    items = _manifest_items(_opf(sb, ["a.png", "b.jpg", "c.jpeg", "d.gif", "e.PNG"], False))
    assert items["img_a_png"] == "image/png"
    assert items["img_b_jpg"] == "image/jpeg"
    assert items["img_c_jpeg"] == "image/jpeg"
    assert items["img_d_gif"] == "image/gif"
    assert items["img_e_PNG"] == "image/png"


def test_cover_meta_matches_manifest_id_for_dotted_filename(sb):
    opf = _opf(sb, ["cover.v2.jpg"], "Images/cover.v2.jpg")
    cover_id = re.search(r'<meta name="cover" content="([^"]+)"/>', opf).group(1)
    assert cover_id in _manifest_items(opf)


def test_cover_meta_matches_manifest_id_for_default_cover(sb):
    opf = _opf(sb, ["default_cover.jpeg"], "default_cover.jpeg")
    cover_id = re.search(r'<meta name="cover" content="([^"]+)"/>', opf).group(1)
    assert cover_id == "img_default_cover_jpeg"
    assert cover_id in _manifest_items(opf)
