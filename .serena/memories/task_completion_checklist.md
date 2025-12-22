# Task Completion Checklist

## Before Marking a Task Complete

### 1. Code Quality
- [ ] Code follows existing naming conventions (snake_case for functions/vars)
- [ ] No syntax errors
- [ ] Error handling added for network/IO operations
- [ ] Uses existing patterns from codebase (Display class for output, etc.)

### 2. Manual Testing (No Automated Tests)
- [ ] Test with a sample book ID if modifying download logic
- [ ] Verify EPUB output if modifying generation logic
- [ ] Test both credential and cookie authentication paths if modifying auth

### 3. Dependencies
- [ ] Any new dependencies added to `requirements.txt`
- [ ] Any new dependencies added to `Pipfile`

### 4. Documentation
- [ ] Update CLAUDE.md if architecture changes
- [ ] Add inline comments for complex logic

### 5. Git Hygiene
- [ ] Changes are atomic and focused
- [ ] Commit messages are descriptive
- [ ] No sensitive data (passwords, cookies) committed

## No Automated Quality Gates
This project lacks:
- Linting configuration (no ruff/flake8/pylint setup)
- Type checking (no mypy, no type hints used)
- Automated tests (no pytest/unittest)
- CI/CD pipeline

Quality assurance is manual verification of functionality.

## Known Limitations
- `.ruff_cache` directory exists but no ruff config found
- No pre-commit hooks configured
- Testing primarily done by downloading sample books
