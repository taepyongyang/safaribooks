"""
Browser-routed HTTP transport for O'Reilly content endpoints.

O'Reilly fronts its content API (/api/v2/epubs/..., chapters, files) with Akamai
Bot Manager in deny-mode for non-browser clients: plain `requests` gets
"403 AkamaiGHost", even with a valid session cookie jar. The only thing that
passes is a request originating from a real, logged-in Chrome (proven: an in-page
fetch() returns 200 while byte-identical cookies from requests return 403).

This module keeps a single logged-in Chrome alive (via the Chrome DevTools
Protocol) for the whole download and issues content requests as in-page fetch()
calls. It returns a small `BrowserResponse` shim that quacks like the parts of
`requests.Response` the pipeline uses (status_code, text, content, json, headers),
so the rest of the codebase is unchanged.

Only GETs are routed here; the lenient /search auth endpoint also works, so the
same transport serves auth checks too.
"""
import atexit
import base64
import json
import os
import stat
import time

import requests

from safaribooks_browser_auth import (
    launch_chrome_with_debugging,
    wait_for_cdp_ready,
    CDP_PORT,
)

HOME_URL = "https://learning.oreilly.com/home/"
ORIGIN = "https://learning.oreilly.com"

# Runs inside the page. Fetches `url`, returns status + headers + base64 body.
# base64 of the raw bytes works uniformly for JSON/HTML (text) and images/fonts
# (binary); Python decodes once and exposes both .content and .text.
_FETCH_JS = """(async () => {
  try {
    const r = await fetch(%s, { credentials: "include" });
    const bytes = new Uint8Array(await r.arrayBuffer());
    let bin = "";
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    const headers = {};
    r.headers.forEach((v, k) => { headers[k] = v; });
    return { status: r.status, url: r.url, headers: headers, b64: btoa(bin) };
  } catch (e) {
    return { status: 0, error: String(e) };
  }
})()"""


class BrowserResponse:
    """Minimal stand-in for requests.Response over a CDP in-page fetch()."""

    def __init__(self, status, body, headers, url):
        self.status_code = status
        self.content = body or b""
        self.headers = headers or {}
        self.url = url
        self.ok = 200 <= status < 300
        # Redirects are followed by fetch() itself, so the pipeline never recurses.
        self.is_redirect = False
        self.next = None

    @property
    def text(self):
        return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)

    def iter_content(self, chunk_size=1024):
        data = self.content
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]


class BrowserTransport:
    def __init__(self, cookies_file, display):
        self._cookies_file = cookies_file
        self.display = display
        self._proc = None
        self._ws = None
        self._id = 0
        self.active = False

    # ---- CDP plumbing -----------------------------------------------------
    def _cmd(self, method, params=None, timeout=30):
        self._id += 1
        mid = self._id
        self._ws.settimeout(timeout)
        self._ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self._ws.recv())
            if msg.get("id") == mid:
                return msg
            # otherwise it's an async event; ignore and keep reading

    def _eval(self, expression, await_promise=False, timeout=30):
        res = self._cmd("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": await_promise,
            "returnByValue": True,
        }, timeout=timeout)
        return res.get("result", {}).get("result", {}).get("value")

    def _navigate(self, url, timeout=30):
        self._cmd("Page.navigate", {"url": url}, timeout=timeout)
        for _ in range(timeout * 2):
            if self._eval("document.readyState") == "complete":
                return
            time.sleep(0.5)

    def _logged_in(self):
        href = self._eval("location.href") or ""
        return "oreilly.com" in href and "/login" not in href

    def _inject_cookies(self):
        if not os.path.isfile(self._cookies_file):
            return 0
        try:
            with open(self._cookies_file) as f:
                jar = json.load(f)
        except (json.JSONDecodeError, IOError):
            return 0
        n = 0
        for name, value in jar.items():
            try:
                self._cmd("Network.setCookie",
                          {"name": name, "value": str(value), "url": ORIGIN})
                n += 1
            except Exception:
                pass
        return n

    # ---- lifecycle --------------------------------------------------------
    def start(self):
        try:
            import websocket  # noqa: F401
        except ImportError:
            raise ImportError(
                "websocket-client is required for browser transport.\n"
                "Install it with: pip install websocket-client"
            )
        import websocket

        self.display.info("Starting browser session (Akamai bypass)...", state=True)
        self._proc = launch_chrome_with_debugging(HOME_URL)
        atexit.register(self.close)  # never orphan Chrome, even on abort
        if not wait_for_cdp_ready(timeout=15):
            raise RuntimeError(
                f"Chrome DevTools not responding on port {CDP_PORT}. "
                "Is another Chrome using it?"
            )

        targets = requests.get(f"http://localhost:{CDP_PORT}/json", timeout=5).json()
        page = next((t for t in targets if t.get("type") == "page"), targets[0])
        self._ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=90)
        self._cmd("Page.enable")
        self._cmd("Network.enable")
        self._cmd("Runtime.enable")

        injected = self._inject_cookies()
        if injected:
            self.display.info(f"Restored {injected} saved cookies into browser.", state=True)
        self._navigate(HOME_URL)

        if not self._logged_in():
            # The saved cookies did not yield a session, so they are stale
            # (expired orm-jwt, dead Akamai bm_*/_abck, old csrftoken...).
            # Left in place they make O'Reilly's sign-in silently reset to
            # the email step, so a manual login can never succeed. Wipe them
            # and reload the login page clean before asking the user.
            if injected:
                self._cmd("Network.clearBrowserCookies")
                self.display.info("Saved cookies are stale; cleared them for a fresh login.", state=True)
                self._navigate(HOME_URL)
            print("\n" + "=" * 60)
            print("O'REILLY LOGIN REQUIRED")
            print("=" * 60)
            print("In the Chrome window that opened:")
            print("  1. Log in to your O'Reilly account")
            print("  2. Wait until you see your library/home page")
            print("  3. Return here and press ENTER")
            print("-" * 60)
            input("Press ENTER once you are logged in (Ctrl+C to cancel)... ")
            self._navigate(HOME_URL)
            if not self._logged_in():
                raise RuntimeError(
                    "Still not logged in. Aborting. (Did login complete in the browser?)"
                )

        self.active = True
        self.display.info("Browser session ready; routing content through Chrome.", state=True)

    def fetch(self, url, timeout=90):
        """Issue an in-page fetch(); returns BrowserResponse or None on transport error."""
        expr = _FETCH_JS % json.dumps(url)
        try:
            res = self._cmd("Runtime.evaluate", {
                "expression": expr,
                "awaitPromise": True,
                "returnByValue": True,
            }, timeout=timeout)
        except Exception as e:
            self.display.error(f"Browser fetch failed for {url}: {e}")
            return None

        val = res.get("result", {}).get("result", {}).get("value")
        if not isinstance(val, dict) or not val.get("status"):
            err = (val or {}).get("error") if isinstance(val, dict) else res
            self.display.error(f"Browser fetch error for {url}: {err}")
            return None

        body = base64.b64decode(val["b64"]) if val.get("b64") else b""
        return BrowserResponse(val["status"], body, val.get("headers", {}), val.get("url", url))

    def save_cookies(self, path):
        try:
            res = self._cmd("Network.getAllCookies")
            cookies = res.get("result", {}).get("cookies", [])
            jar = {c["name"]: c["value"] for c in cookies
                   if "oreilly.com" in c.get("domain", "")}
            with open(path, "w") as f:
                json.dump(jar, f)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            return len(jar)
        except Exception:
            return 0

    def close(self):
        self.active = False
        try:
            if self._ws:
                self._ws.close()
        except Exception:
            pass
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.kill()
