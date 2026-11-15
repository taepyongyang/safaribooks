from safaribooks_diagnostics import DiagnosticCollector, FailureCategory
from tests.conftest import BOOK_ID

FILES = "https://learning.oreilly.com/api/v2/epubs/urn:orm:book:9781234567890/files/"


def test_same_name_other_url_is_recorded(sb):
    sb.diagnostics = DiagnosticCollector(enabled=True, book_id=BOOK_ID)
    assert sb._add_image(FILES + "ch01/images/fig1.png", "fig1.png") is True
    assert sb._add_image(FILES + "ch02/images/fig1.png", "fig1.png") is False
    assert sb.images == [FILES + "ch01/images/fig1.png"]
    [failure] = sb.diagnostics.failures
    assert failure.category == FailureCategory.VALIDATION
    assert failure.stage == "images"
    assert failure.url == FILES + "ch02/images/fig1.png"
    assert "fig1.png" in sb.display.log.call_args[0][0]


def test_same_url_twice_is_not_a_collision(sb):
    sb.diagnostics = DiagnosticCollector(enabled=True, book_id=BOOK_ID)
    sb._add_image(FILES + "ch01/images/fig1.png", "fig1.png")
    assert sb._add_image(FILES + "ch01/images/fig1.png", "fig1.png") is False
    assert sb.diagnostics.failures == []
