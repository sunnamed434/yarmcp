# YARMCP Tests

Test suite for security and functionality.

## Quick Start

Install and run:
```bash
pip install -r requirements-test.txt
pytest
```

## Test Files

- `test_security_path_validation.py` - Path traversal, symlinks, CVE protection
- `test_security_oauth.py` - JWT, OAuth flows, token validation
- `test_mcp_tools.py` - All 8 MCP tools functionality

## Common Commands

```bash
# Run all tests
pytest

# With coverage
pytest --cov=. --cov-report=html

# Security tests only
pytest tests/test_security_*.py

# Single test
pytest tests/test_security_oauth.py::TestJWTManager::test_verify_expired_token -v
```

## What's Tested

**Security (40+ tests):**
- Path traversal attacks blocked
- Symlink escapes blocked
- JWT token validation
- OAuth client registration
- Open Redirect vulnerability (documented in tests)

**MCP Tools (25+ tests):**
- list_repos, read_file, search_code
- Path validation on all tools
- README detection

**Target:** 70%+ code coverage
