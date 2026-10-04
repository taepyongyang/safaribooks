import os
import stat

import safaribooks_browser_auth
import safaribooks_config as cfg
from safaribooks_browser_transport import HOME_URL, ORIGIN
from safaribooks_browser_auth import CHROME_PROFILE_DIR


def test_transport_urls_derive_from_config():
    assert HOME_URL == "https://learning.oreilly.com/home/"
    assert ORIGIN == "https://learning.oreilly.com"
    assert HOME_URL.startswith(cfg.SAFARI_BASE_URL)


def test_chrome_profile_dir_comes_from_config():
    expected = os.path.join(os.path.expanduser("~"), ".cache", "safaribooks", "chrome_profile")
    assert CHROME_PROFILE_DIR == cfg.CHROME_PROFILE_DIR == expected


def _launch_with_stubs(monkeypatch, tmp_path):
    profile = tmp_path / "cache" / "safaribooks" / "chrome_profile"
    captured = {}
    monkeypatch.setattr(safaribooks_browser_auth, "CHROME_PROFILE_DIR", str(profile))
    monkeypatch.setattr(safaribooks_browser_auth, "find_chrome_path", lambda: "/fake/chrome")
    monkeypatch.setattr(safaribooks_browser_auth.subprocess, "Popen",
                        lambda args, **kw: captured.setdefault("args", args))
    safaribooks_browser_auth.launch_chrome_with_debugging("https://example.invalid/")
    return profile, captured["args"]


def test_chrome_launch_does_not_allow_foreign_websocket_origins(monkeypatch, tmp_path):
    _, args = _launch_with_stubs(monkeypatch, tmp_path)
    assert not any(a.startswith("--remote-allow-origins") for a in args)


def test_chrome_profile_is_private_to_user(monkeypatch, tmp_path):
    profile, args = _launch_with_stubs(monkeypatch, tmp_path)
    assert f"--user-data-dir={profile}" in args
    assert stat.S_IMODE(profile.stat().st_mode) == 0o700
    assert stat.S_IMODE(profile.parent.stat().st_mode) == 0o700


def test_chrome_profile_permissions_are_tightened_if_dir_already_exists(monkeypatch, tmp_path):
    profile = tmp_path / "cache" / "safaribooks" / "chrome_profile"
    profile.mkdir(parents=True, mode=0o755)
    os.chmod(profile, 0o755)
    _launch_with_stubs(monkeypatch, tmp_path)
    assert stat.S_IMODE(profile.stat().st_mode) == 0o700


def test_config_has_no_legacy_constants():
    for name in ["PROFILE_URL", "API_ORIGIN_URL", "ORLY_BASE_URL",
                 "REGISTER_URL", "CHECK_EMAIL", "CHECK_PWD", "CSRF_TOKEN_RE",
                 "USE_PROXY", "PROXIES"]:
        assert not hasattr(cfg, name), name
