# Session: OpenSSL/Blake2 Warning Fix

**Date**: 2026-01-26
**Issue**: Blake2 hash algorithm warnings at Python startup
**Resolution**: Environment fix (no code changes)

## Problem

When running `safaribooks_refactored.py`, Python 3.13.3 (pyenv) displayed:
```
ERROR:root:code for hash blake2b was not found.
ValueError: unsupported hash type blake2b
ERROR:root:code for hash blake2s was not found.
ValueError: unsupported hash type blake2s
```

## Root Cause

- Python was compiled via pyenv against an older OpenSSL lacking BLAKE2 support
- The `hashlib` module tries to register all hash algorithms at import time
- When a dependency imports `hashlib`, Python fails to load blake2b/blake2s
- SafariBooks code does NOT use blake2 directly - issue comes from transitive dependencies (requests → urllib3)

## Investigation Findings

- Searched all 9 Python files: NO direct `hashlib` or `blake2` usage
- Dependencies (requests, urllib3, lxml) don't explicitly use blake2
- Issue is purely environmental, not code-related

## Solution Applied

Reinstalled Python via pyenv, which picked up the updated OpenSSL:
```bash
brew upgrade openssl@3
pyenv uninstall 3.13.3
pyenv install 3.13.3
```

For explicit OpenSSL linking (if needed):
```bash
LDFLAGS="-L$(brew --prefix openssl@3)/lib" \
CPPFLAGS="-I$(brew --prefix openssl@3)/include" \
PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig" \
pyenv install 3.13.3
```

## Verification

```bash
python3 -c "import hashlib; print('blake2b' in hashlib.algorithms_available)"
# Returns: True (fixed)
```

## Key Learnings

1. pyenv Python installs link against system OpenSSL at compile time
2. Upgrading OpenSSL alone doesn't fix existing Python installs - must rebuild
3. This is a common issue on macOS with Homebrew's OpenSSL/LibreSSL configurations
4. No code changes were needed for SafariBooks
