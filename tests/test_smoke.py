def test_fixture_builds_without_running_pipeline(sb):
    assert sb.book_id == "9781234567890"
    assert sb.debug is False
