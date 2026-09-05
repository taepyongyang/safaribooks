# Session 2026-08-30: Stale-cookie login reset fix

## Problem
Since `cookies.json` expired (JWT exp 2026-06-22), every download failed at the manual-login step: user enters email+password in the transport Chrome, sees "Signing in…", is bounced back to the empty email form. Aug 10 log (`info_0642572428914.log`) shows 3 attempts all dying there.

## Root cause (confirmed by A/B, not theory)
`BrowserTransport.start()` injected all 26 saved cookies via `Network.setCookie` *before* prompting for manual login. Stale set (expired `orm-jwt`, dead `orm-rt`/`groot_sessionid`/`csrftoken`, Akamai `_abck`/`bm_*` from a dead session) makes O'Reilly's sign-in silently reset. Two fresh identical profiles, same credentials typed in both: injected → bounced at t=16s; clean → `learning.oreilly.com/home2/` at t=12s. Not bisected to a single cookie (each bisect costs a manual login).

Latent since the transport was written (Jun 2026): valid cookies always auto-logged in, so the expired branch was never exercised with stale cookies present. Unrelated to the Jun Akamai 403 (`mem:session_2026-02-24_v2_api_migration`, auto-memory `akamai-403-headers`).

## Fix — commit b270abb
`safaribooks_browser_transport.py` `start()`: if `_logged_in()` is false after injection, `Network.clearBrowserCookies` → re-navigate HOME_URL → then show login prompt. Ten lines, nothing else touched.

## Verification
Full download of `9781633436015` (Build Python Web Apps with Streamlit): diagnostic SUCCESS, 29/29 chapters, 186/186 images, 1/1 CSS + 1 font, 182 s. `cookies.json` refreshed (28 cookies).

## Learned
- Logged-in landing is now `/home2/`; `_logged_in()` still passes.
- Fresh `orm-jwt` is short-lived (~15 min); cross-run auto-login relies on `orm-rt` refresh on page load.
- Chrome 152 + the script's flags is stable (150 s liveness probe, no crash reports). Persistent profile `/tmp/safaribooks_chrome_profile`.
- Login prompt is `input()` → closed-stdin runs abort "EOF when reading a line"; reproduction must be interactive (`! python3 safaribooks_refactored.py --debug --preserve-log <id>`).
- Log files can contain binary (image bodies via `last_request` dumps) — grep with `-a`.

## Left uncommitted
`.serena/project.yml` (Serena template migration, harmless); `cookies.json.bak` untracked, holds tokens, NOT gitignored — never stage.

## Possible follow-up (not done)
Skip injection entirely when the saved `orm-jwt` is already expired, so a still-valid session in the persistent Chrome profile isn't clobbered.
