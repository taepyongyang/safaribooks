# Session 2026-10-03/04: CDP port lockdown + Chrome profile move

Branch `refactor-codebase`, commit `30f2fb5`, pushed to origin. Picked from the follow-ups in `mem:session_2026-09-05_structural_cleanup`.

## Problem
- `launch_chrome_with_debugging` passed `--remote-allow-origins=*` (comment wrongly said "from localhost"). Any web page open in any browser during a download could open `ws://localhost:9222/...` and drive the logged-in O'Reilly Chrome (cookies, scripts).
- Profile at `/tmp/safaribooks_chrome_profile` held live session cookies, persisted between runs.

## Fix
- Flag removed. Transport connects with `websocket.create_connection(..., suppress_origin=True)` (`safaribooks_browser_transport.py`, in `start()`). Chrome (111+) accepts DevTools websocket connections with no Origin header and refuses ones with a non-allowed Origin; browsers always send one. websocket-client 1.9.0's default Origin would be refused without the flag, which is why the flag existed.
- `CHROME_PROFILE_DIR` = `~/.cache/safaribooks/chrome_profile` (`os.path.expanduser`). `launch_chrome_with_debugging` does `mkdir(parents=True, exist_ok=True)` then `os.chmod(0o700)` on the profile and its parent every launch (mkdir mode alone is umask-affected and skipped for existing dirs).
- Old `/tmp/safaribooks_chrome_profile` was already absent on the user's machine; nothing to clean.
- Tests: `tests/test_config.py` profile-path expectation updated; 3 new tests stub `find_chrome_path` and `subprocess.Popen` to assert no `--remote-allow-origins` arg, 0700 on fresh dirs, and tightening of a pre-existing 0755 dir. 50 tests pass, ruff clean.
- CLAUDE.md transport bullet updated ("Don't re-add `--remote-allow-origins=*`"); same commit also carried the user's pending CLAUDE.md edits (pytest single-test commands, WinQueue entry, ~1850 lines).

## Verification
- User ran a real download: works. `~/.cache/safaribooks` and `chrome_profile` are `drwx------`.
- Not directly verified: that a foreign origin is refused (Chrome default behaviour). Scratch script `/tmp/claude-501/cdp_origin_check.py` (headless Chrome on port 9333; prints CONNECTED/REFUSED for default origin, suppress_origin, evil origin) — run with `PYTHONPATH=.` from repo root. Ephemeral location.

## Process notes
- Launching Chrome from Claude Code fails inside the sandbox; running it with the sandbox disabled was denied by the auto-mode classifier. Live Chrome checks must be run by the user.
- The morph edit tool strips the trailing newline from every file it edits; restore with `[ -n "$(tail -c1 f)" ] && echo >> f`. It also can't edit outside the repo (use Edit for `~/.claude/...` memory).

## Also this session
- `.gitignore`: added `cookies.json.bak` (line 19). Uncommitted at save time; user offered `cookies.json.*` pattern as an alternative.
- TypeSafe plugin (`typesafe@typesafe-ai`, skill `/typesafe:typesafe-ai`, model Jev) is enabled with `TYPESAFE_API_KEY` set; smoke-tested `POST https://api.typesafe.ai/v1/systemone` with `jev-latest` → 200, served `jev-1.13.0`. Unrelated to this project's code.

## Remaining follow-ups
- Deferred: pin `pytest` in requirements.txt; delete unreachable `if args.cred:` note.
- SVG cover extension `svg+xml` (`safaribooks_process.py` ~line 540, `content_type.split("/")[-1]`).
- Review items 1–4: `run()` out of `__init__`, split `SafariBooks`, explicit pipeline state, `SafariBooksError` instead of `display.exit()`.
- Hygiene: bare `open().write()` calls; `print(cookies)` in `sso_cookies.py`.
