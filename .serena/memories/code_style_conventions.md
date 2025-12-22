# Code Style and Conventions

## Naming Conventions
- **Variables/Functions**: `snake_case` (e.g., `book_chapters`, `do_login`)
- **Classes**: `PascalCase` (e.g., `SafariBooks`, `Display`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `COOKIES_FILE`, `API_ORIGIN_URL`)
- **Private methods**: Prefix with underscore `_` (e.g., `_thread_download_css`)

## Code Patterns

### String Formatting
- Primarily uses old-style `%` operator for string formatting
- Some f-strings present but not consistently used
```python
"info_%s.log" % escape(args.bookid)
"Downloading book contents... (%s chapters)" % len(self.book_chapters)
```

### Type Hints
- **Not used** in this codebase
- All function parameters and return types are untyped

### Docstrings
- **Minimal docstrings** - mostly inline comments
- No formal docstring format (Google, NumPy, etc.) adopted

### Error Handling
- Uses `self.display.exit()` for fatal errors with descriptive messages
- Try/except blocks for specific operations (parsing, network)
- Custom Display class handles logging and error output

### Class Structure Pattern
```python
class ClassName:
    CONSTANT = "value"  # Class constants at top
    
    def __init__(self, args):
        # Instance initialization
        self.attribute = value
    
    def public_method(self):
        # Public methods
        pass
    
    def _private_method(self):
        # Private helper methods prefixed with _
        pass
```

### Import Organization
- Standard library imports first
- Third-party imports second
- Local imports third
- No strict alphabetical ordering enforced

### File Organization
- Entry point: `safaribooks_refactored.py`
- Core logic: `safaribooks_process.py`
- Display/logging: `safaribooks_display.py`
- Configuration: `safaribooks_config.py`
- Utilities: `sso_cookies.py`, `safaribooks_winqueue.py`
