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
