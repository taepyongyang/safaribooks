"""
Browser-based authentication using Chrome DevTools Protocol.

This module provides AWS SSO-style login: launches Chrome with remote debugging,
lets the user log in manually (bypassing bot detection), then extracts cookies
via the Chrome DevTools Protocol.

Usage:
    from safaribooks_browser_auth import browser_login
    cookies = browser_login()  # Returns dict of cookies
"""

import json
import os
import platform
import stat
import subprocess
import time
from pathlib import Path

import requests

# Configuration
CDP_PORT = 9222
CDP_TIMEOUT = 5  # Seconds to wait for Chrome to start
OREILLY_LOGIN_URL = "https://learning.oreilly.com/accounts/login/"
OREILLY_DOMAINS = [".oreilly.com", "learning.oreilly.com", "www.oreilly.com"]


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
    temp_profile = Path("/tmp/safaribooks_chrome_profile")
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


def get_cookies_via_cdp() -> list[dict]:
    """
    Connect to Chrome via CDP and extract all cookies.

    Returns:
        List of cookie dictionaries from Chrome

    Raises:
        RuntimeError: If unable to connect to Chrome or extract cookies
    """
    try:
        # Import websocket here to defer the dependency check
        import websocket
    except ImportError:
        raise ImportError(
            "websocket-client is required for browser authentication.\n"
            "Install it with: pip install websocket-client"
        )

    # Get WebSocket URL from CDP
    try:
        response = requests.get(f"http://localhost:{CDP_PORT}/json", timeout=5)
        targets = response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to connect to Chrome DevTools: {e}")

    if not targets:
        raise RuntimeError("No browser targets found. Is Chrome running with remote debugging?")

    # Find a page target (not extension or service worker)
    page_target = None
    for target in targets:
        if target.get("type") == "page":
            page_target = target
            break

    if not page_target:
        page_target = targets[0]  # Fallback to first target

    ws_url = page_target.get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError("Could not get WebSocket URL from Chrome DevTools")

    # Connect via WebSocket and get cookies
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        ws.send(json.dumps({
            "id": 1,
            "method": "Network.getAllCookies"
        }))
        result = json.loads(ws.recv())
        ws.close()
    except Exception as e:
        raise RuntimeError(f"Failed to extract cookies via CDP: {e}")

    if "error" in result:
        raise RuntimeError(f"CDP error: {result['error']}")

    return result.get("result", {}).get("cookies", [])


def filter_oreilly_cookies(cookies: list[dict]) -> dict:
    """
    Filter and format O'Reilly cookies for the requests library.

    Args:
        cookies: List of cookie dicts from Chrome CDP

    Returns:
        Dictionary of {name: value} for O'Reilly cookies
    """
    oreilly_cookies = {}

    for cookie in cookies:
        domain = cookie.get("domain", "")
        # Check if cookie belongs to O'Reilly
        if any(d in domain or domain.endswith(d) for d in OREILLY_DOMAINS):
            oreilly_cookies[cookie["name"]] = cookie["value"]

    return oreilly_cookies


def browser_login(cookies_file: str = "cookies.json") -> dict:
    """
    Main function: Launch browser, wait for login, extract cookies.

    This provides an AWS SSO-style login experience:
    1. Opens Chrome to O'Reilly login page
    2. User logs in manually (bypasses bot detection)
    3. User presses ENTER when done
    4. Cookies are extracted and saved

    Args:
        cookies_file: Path to save cookies (default: cookies.json)

    Returns:
        Dictionary of cookies suitable for requests library

    Raises:
        ValueError: If no O'Reilly cookies found after login
        FileNotFoundError: If Chrome is not installed
        RuntimeError: If CDP connection fails
    """
    print("\n" + "=" * 60)
    print("BROWSER LOGIN REQUIRED")
    print("=" * 60)
    print("\nOpening Chrome browser for O'Reilly login...")
    print("(A separate Chrome window will open)\n")

    chrome_process = None

    try:
        chrome_process = launch_chrome_with_debugging(OREILLY_LOGIN_URL)

        # Wait for Chrome to start and CDP to be ready
        if not wait_for_cdp_ready():
            raise RuntimeError(
                "Chrome DevTools Protocol not responding.\n"
                "Please ensure Chrome started correctly and no other instance "
                f"is using port {CDP_PORT}."
            )

        print("Browser opened successfully!")
        print("\nPlease complete the following steps:")
        print("  1. Log in to your O'Reilly account in the browser")
        print("  2. Wait for the login to complete (you should see your library)")
        print("  3. Come back here and press ENTER")
        print("\n" + "-" * 60)

        input("Press ENTER when you have completed login (or Ctrl+C to cancel)... ")

        print("\nExtracting cookies...")
        cookies = get_cookies_via_cdp()
        oreilly_cookies = filter_oreilly_cookies(cookies)

        if not oreilly_cookies:
            raise ValueError(
                "No O'Reilly cookies found.\n"
                "Please make sure you:\n"
                "  - Logged in successfully\n"
                "  - Are on a learning.oreilly.com page\n"
                "  - Waited for the page to fully load"
            )

        # Save cookies to file with secure permissions
        with open(cookies_file, 'w') as f:
            json.dump(oreilly_cookies, f, indent=2)
        os.chmod(cookies_file, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

        print(f"\n[OK] Captured {len(oreilly_cookies)} cookies")
        print(f"[OK] Saved to {cookies_file}")
        print("=" * 60 + "\n")

        return oreilly_cookies

    except KeyboardInterrupt:
        print("\n\nLogin cancelled by user.")
        raise

    finally:
        if chrome_process:
            chrome_process.terminate()
            # Give it a moment to close gracefully
            try:
                chrome_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                chrome_process.kill()


def validate_cookies(cookies: dict, api_url: str, timeout: int = 30) -> tuple[bool, str]:
    """
    Validate if cookies are still valid by making a test API request.

    Args:
        cookies: Dictionary of cookies
        api_url: API endpoint to test (should return 401 if unauthorized)
        timeout: Request timeout in seconds

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        session = requests.Session()
        session.cookies.update(cookies)
        response = session.get(api_url, timeout=timeout)

        if response.status_code == 401:
            return False, "Session expired or invalid"
        elif response.status_code == 403:
            return False, "Access forbidden - account may be restricted"
        elif response.status_code >= 400:
            return False, f"API error: HTTP {response.status_code}"

        return True, ""

    except requests.Timeout:
        return False, "Connection timeout"
    except requests.ConnectionError:
        return False, "Connection error - check your internet"
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    # Test the browser login when run directly
    try:
        cookies = browser_login()
        print(f"Successfully extracted {len(cookies)} cookies:")
        for name in sorted(cookies.keys()):
            print(f"  - {name}")
    except Exception as e:
        print(f"Error: {e}")
