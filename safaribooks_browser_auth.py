"""
Chrome discovery and launch helpers for the browser-routed transport.

Launches Chrome with the DevTools Protocol enabled on CDP_PORT and a throwaway
profile, and waits until the /json endpoint answers. The transport module
(`safaribooks_browser_transport.py`) does everything else over the resulting
websocket.
"""

import os
import platform
import subprocess
import time
from pathlib import Path

import requests

from safaribooks_config import CHROME_PROFILE_DIR

# Configuration
CDP_PORT = 9222
CDP_TIMEOUT = 5  # Seconds to wait for Chrome to start


def find_chrome_path() -> str:
    """
    Find Chrome/Chromium executable based on platform.

    Returns:
        Path to Chrome executable

    Raises:
        FileNotFoundError: If Chrome is not installed
    """
    system = platform.system()

    if system == "Darwin":  # macOS
        paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    elif system == "Windows":
        paths = [
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
    else:  # Linux
        paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
        ]

    for path in paths:
        if Path(path).exists():
            return path

    raise FileNotFoundError(
        "Chrome/Chromium not found. Please install Google Chrome.\n"
        f"Searched paths: {paths}"
    )


def launch_chrome_with_debugging(url: str) -> subprocess.Popen:
    """
    Launch Chrome with remote debugging enabled.

    Args:
        url: URL to open in Chrome

    Returns:
        Popen process handle for the Chrome instance
    """
    chrome_path = find_chrome_path()

    # Use a temporary user data directory to avoid conflicts with existing Chrome
    temp_profile = Path(CHROME_PROFILE_DIR)
    temp_profile.mkdir(exist_ok=True)

    args = [
        chrome_path,
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-allow-origins=*",  # Allow WebSocket connections from localhost
        f"--user-data-dir={temp_profile}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-hang-monitor",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-sync",
        "--disable-translate",
        "--metrics-recording-only",
        "--safebrowsing-disable-auto-update",
        url
    ]

    return subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def wait_for_cdp_ready(timeout: int = CDP_TIMEOUT) -> bool:
    """
    Wait for Chrome DevTools Protocol to be ready.

    Args:
        timeout: Maximum seconds to wait

    Returns:
        True if CDP is ready, False if timeout
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(f"http://localhost:{CDP_PORT}/json", timeout=1)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False
