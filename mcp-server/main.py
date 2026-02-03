import os
import subprocess
import re
import secrets
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode, parse_qs, urlparse

from fastmcp import FastMCP
from pydantic import Field

from config import (
    settings,
    load_repos_config,
    get_repo_path,
    get_repo_last_updated,
    get_repo_commit_hash,
)
from security.path_validator import validate_repo_path, validate_repo_name
from security.auth import verify_auth_token
from security.storage import TTLDict, ClientStorage, AuthCodeData
from security.pkce import verify_code_challenge, is_valid_challenge
from security.oauth import JWTManager, generate_authorization_code, generate_jwt_secret


# Initialize FastMCP server
mcp = FastMCP("YARMCP")


# Initialize OAuth components
_jwt_secret = settings.oauth_jwt_secret or generate_jwt_secret()
_jwt_manager: JWTManager | None = None
_auth_codes = TTLDict(ttl_seconds=settings.oauth_auth_code_expiry)
_client_storage: ClientStorage | None = None


def get_jwt_manager(issuer: str) -> JWTManager:
    """Get or create JWT manager with the given issuer."""
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = JWTManager(
            secret_key=_jwt_secret,
            issuer=issuer,
            default_expiry=settings.oauth_token_expiry,
        )
    return _jwt_manager


def get_client_storage() -> ClientStorage:
    """Get or create client storage."""
    global _client_storage
    if _client_storage is None:
        _client_storage = ClientStorage(
            file_path=settings.oauth_clients_file,
            preconfigured_client_id=settings.oauth_client_id,
            preconfigured_client_secret=settings.oauth_client_secret,
            max_clients=settings.oauth_dcr_max_clients,
        )
    return _client_storage


def get_issuer_url(request) -> str:
    """Get the issuer URL from request or config."""
    if settings.oauth_issuer:
        return settings.oauth_issuer.rstrip("/")
    # Auto-detect from request
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}"


def validate_redirect_uri(redirect_uri: str, allowed_uris: list[str]) -> bool:
    """
    Validate redirect URI against allowed patterns.

    Supports:
    - Exact match: "http://localhost:3000/callback"
    - Wildcard "*": allow any URI
    - Port wildcard: "http://localhost:*" matches "http://localhost:3000"
    - Path wildcard: "https://example.com/*" matches "https://example.com/callback"

    Args:
        redirect_uri: The redirect URI to validate
        allowed_uris: List of allowed URI patterns

    Returns:
        True if redirect_uri matches any allowed pattern
    """
    # Check for wildcard (allow any)
    if "*" in allowed_uris:
        return True

    # Check exact match
    if redirect_uri in allowed_uris:
        return True

    # Parse the redirect URI
    parsed = urlparse(redirect_uri)

    # Check pattern matches
    for pattern in allowed_uris:
        # Port wildcard: http://localhost:* matches http://localhost:3000
        if ":*" in pattern:
            pattern_without_port = pattern.replace(":*", "")
            redirect_without_port = f"{parsed.scheme}://{parsed.hostname}"
            if pattern_without_port == redirect_without_port:
                return True

        # Path wildcard: https://example.com/* matches https://example.com/callback
        if pattern.endswith("/*"):
            pattern_base = pattern[:-2]  # Remove /*
            if redirect_uri.startswith(pattern_base):
                return True

    return False


# Authentication middleware
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from fastmcp.exceptions import ToolError


# Public paths that don't require authentication
PUBLIC_PATHS = {
    "/health",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/token",
}


class AuthenticationMiddleware(Middleware):
    """Middleware to enforce bearer token authentication on all MCP requests."""

    def _get_issuer_from_headers(self, headers: dict) -> str:
        """Extract issuer URL from headers, matching token endpoint logic."""
        if settings.oauth_issuer:
            return settings.oauth_issuer.rstrip("/")
        # Auto-detect from forwarded headers (same logic as get_issuer_url)
        scheme = headers.get("x-forwarded-proto", "https")
        host = headers.get("x-forwarded-host", headers.get("host", "localhost"))
        return f"{scheme}://{host}"

    async def on_request(self, context: MiddlewareContext, call_next):
        """Authenticate all MCP requests."""
        headers = get_http_headers() or {}

        # Extract bearer token
        auth_header = headers.get("authorization", "")
        token = None

        if auth_header:
            parts = auth_header.split(" ", 1)
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]

        if not token:
            raise ToolError("Unauthorized: Missing authentication token")

        # Try OAuth JWT token first (uses _jwt_secret which is always available)
        if settings.oauth_enabled:
            issuer = self._get_issuer_from_headers(headers)
            jwt_mgr = get_jwt_manager(issuer)
            token_data = jwt_mgr.verify_access_token(token)
            if token_data:
                # Valid OAuth token
                return await call_next(context)

        # Fall back to static bearer token
        if verify_auth_token(token):
            return await call_next(context)

        raise ToolError("Unauthorized: Invalid authentication token")


# Add middleware to FastMCP
mcp.add_middleware(AuthenticationMiddleware())


@mcp.tool()
def list_repos() -> list[dict]:
    """
    List all available repositories in the registry.
    Returns repository names, descriptions, and last update times.
    """
    config = load_repos_config()
    repos = []

    for repo in config.repos:
        repo_path = get_repo_path(repo.name)
        repos.append({
            "name": repo.name,
            "description": repo.description,
            "branch": repo.branch,
            "available": repo_path.exists(),
            "last_updated": get_repo_last_updated(repo.name),
        })

    return repos


@mcp.tool()
def get_repo_info(
    repo: Annotated[str, Field(description="Repository name from list_repos()")]
) -> dict:
    """
    Get detailed information about a specific repository.
    Returns metadata including URL, branch, last update time, and current commit.
    """
    validate_repo_name(repo)
    config = load_repos_config()

    repo_config = next((r for r in config.repos if r.name == repo), None)
    if not repo_config:
        raise ValueError(f"Repository '{repo}' not found in registry")

    repo_path = get_repo_path(repo)

    return {
        "name": repo_config.name,
        "url": repo_config.url,
        "branch": repo_config.branch,
        "description": repo_config.description,
        "private": repo_config.private,
        "available": repo_path.exists(),
        "last_updated": get_repo_last_updated(repo),
        "commit_hash": get_repo_commit_hash(repo),
    }


@mcp.tool()
def read_file(
    repo: Annotated[str, Field(description="Repository name")],
    path: Annotated[str, Field(description="File path relative to repository root")],
) -> str:
    """
    Read a file from a repository.
    Returns the file content as a string.
    """
    validate_repo_name(repo)
    full_path = validate_repo_path(repo, path)

    if not full_path.exists():
        # Enhanced error with suggestions
        parent_exists = full_path.parent.exists()
        similar_files = _find_similar_files(full_path) if parent_exists else []

        error_msg = f"File not found: {path}"
        if parent_exists:
            error_msg += " (directory exists)"

        if similar_files:
            error_msg += f"\n\nSimilar files in {full_path.parent.name}/:\n"
            error_msg += "\n".join(f"  - {f}" for f in similar_files[:3])

        raise FileNotFoundError(error_msg)

    if not full_path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    # Limit file size to prevent memory issues
    max_size = 10 * 1024 * 1024  # 10MB
    if full_path.stat().st_size > max_size:
        raise ValueError(f"File too large (max {max_size // 1024 // 1024}MB)")

    return full_path.read_text(encoding="utf-8", errors="replace")


@mcp.tool()
def search_code(
    repo: Annotated[str, Field(description="Repository name")],
    pattern: Annotated[str, Field(description="Search pattern (regex supported)")],
    file_pattern: Annotated[str | None, Field(description="File glob pattern, e.g. '*.ts'")] = None,
    max_results: Annotated[int, Field(description="Maximum results to return")] = 100,
    context_lines: Annotated[int, Field(description="Lines of context before/after match")] = 2,
) -> dict:
    """
    Search for code patterns in a repository using ripgrep.
    Returns matching lines with file paths, line numbers, and search metadata.
    """
    import json
    import time

    validate_repo_name(repo)
    repo_path = get_repo_path(repo)

    if not repo_path.exists():
        raise ValueError(f"Repository '{repo}' not available (not cloned)")

    cmd = [
        "rg",
        "--json",
        "--max-count", str(max_results),
        "--max-filesize", "10M",
        "-C", str(context_lines),
        "--no-heading",
        "--stats",  # Get statistics
    ]

    if file_pattern:
        cmd.extend(["--glob", file_pattern])

    cmd.extend([pattern, str(repo_path)])

    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("Search timed out (60s limit)")

    search_time_ms = int((time.time() - start_time) * 1000)

    # Parse ripgrep JSON output
    matches = []
    files_searched = 0

    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        try:
            data = json.loads(line)

            if data.get("type") == "match":
                match_data = data["data"]
                # Make path relative to repo
                abs_path = Path(match_data["path"]["text"])
                rel_path = abs_path.relative_to(repo_path)

                matches.append({
                    "file": str(rel_path),
                    "line": match_data["line_number"],
                    "content": match_data["lines"]["text"].rstrip(),
                })

            elif data.get("type") == "summary":
                # Extract statistics from ripgrep summary
                stats = data.get("data", {})
                files_searched = stats.get("stats", {}).get("searches", 0)

        except (json.JSONDecodeError, KeyError):
            continue

    # Build response with metadata
    response = {
        "matches": matches[:max_results],
        "meta": {
            "total_matches": len(matches),
            "returned_matches": min(len(matches), max_results),
            "search_time_ms": search_time_ms,
            "pattern": pattern,
        }
    }

    # Add hint if no results
    if not matches:
        response["meta"]["hint"] = "No matches found. Try a broader pattern or use list_files to explore the repository structure."

    if file_pattern:
        response["meta"]["file_pattern"] = file_pattern

    if files_searched > 0:
        response["meta"]["files_searched"] = files_searched

    return response


@mcp.tool()
def list_files(
    repo: Annotated[str, Field(description="Repository name")],
    path: Annotated[str, Field(description="Directory path relative to repo root")] = "",
    pattern: Annotated[str | None, Field(description="Glob pattern to filter files")] = None,
) -> list[dict]:
    """
    List files and directories in a repository path.
    Returns file names, types (file/directory), and sizes.
    """
    validate_repo_name(repo)

    if path:
        full_path = validate_repo_path(repo, path)
    else:
        full_path = get_repo_path(repo)

    if not full_path.exists():
        raise FileNotFoundError(f"Path not found: {path or '/'}")

    if not full_path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    entries = []

    if pattern:
        # Use glob pattern
        for item in full_path.glob(pattern):
            if item.name.startswith("."):
                continue
            entries.append(_file_entry(item, full_path))
    else:
        # List directory contents
        for item in sorted(full_path.iterdir()):
            if item.name.startswith("."):
                continue
            entries.append(_file_entry(item, full_path))

    return entries[:1000]  # Limit to 1000 entries


def _file_entry(item: Path, base_path: Path, include_preview: bool = True) -> dict:
    """Create a file entry dict with optional directory preview."""
    rel_path = item.relative_to(base_path)
    entry = {
        "name": str(rel_path),
        "type": "directory" if item.is_dir() else "file",
    }

    if item.is_file():
        entry["size"] = item.stat().st_size
    elif item.is_dir() and include_preview:
        # Add preview for directories
        try:
            children = list(item.iterdir())
            # Filter out hidden files
            visible_children = [c for c in children if not c.name.startswith(".")]

            file_count = sum(1 for c in visible_children if c.is_file())
            dir_count = sum(1 for c in visible_children if c.is_dir())

            entry["file_count"] = file_count
            entry["dir_count"] = dir_count

            # Preview first 3 items
            preview_items = sorted(visible_children, key=lambda x: (not x.is_dir(), x.name))[:3]
            entry["preview"] = [c.name for c in preview_items]

            if len(visible_children) > 3:
                entry["preview"].append("...")

        except (PermissionError, OSError):
            entry["preview"] = ["(access denied)"]

    return entry


def _find_similar_files(target_path: Path, max_suggestions: int = 5) -> list[str]:
    """Find similar files in the same directory and parent directories."""
    suggestions = []

    # Get parent directory
    parent = target_path.parent
    if not parent.exists():
        return suggestions

    # Get target stem for similarity matching
    target_stem = target_path.stem.lower()

    # Search in parent directory
    try:
        for item in parent.iterdir():
            if item.is_file() and not item.name.startswith("."):
                # Calculate simple similarity (contains target stem)
                if target_stem in item.name.lower():
                    suggestions.append(str(item.relative_to(parent.parent)))
                    if len(suggestions) >= max_suggestions:
                        break
    except (PermissionError, OSError):
        pass

    return suggestions


@mcp.tool()
def get_readme(
    repo: Annotated[str, Field(description="Repository name")]
) -> str:
    """
    Get the README file from a repository.
    Searches for README.md, README, README.txt in the repository root.
    """
    validate_repo_name(repo)
    repo_path = get_repo_path(repo)

    if not repo_path.exists():
        raise ValueError(f"Repository '{repo}' not available (not cloned)")

    # Common README file names
    readme_names = ["README.md", "README", "README.txt", "readme.md", "Readme.md"]

    for name in readme_names:
        readme_path = repo_path / name
        if readme_path.exists() and readme_path.is_file():
            return readme_path.read_text(encoding="utf-8", errors="replace")

    raise FileNotFoundError(f"No README found in repository '{repo}'")


@mcp.tool()
def get_yarmcp_usage_guide() -> str:
    """
    Get usage guide and examples for YARMCP tools.
    Returns comprehensive documentation with common usage patterns and tips.
    """
    return """# YARMCP Usage Guide

## Available Tools

### 1. list_repos()
List all configured repositories with their status.

**Example:**
```python
list_repos()
# Returns: [{"name": "react", "available": true, "last_updated": "2024-01-15T10:30:00Z"}, ...]
```

### 2. get_repo_info(repo)
Get detailed repository metadata including current commit.

**Example:**
```python
get_repo_info("react")
# Returns: {"name": "react", "url": "...", "commit_hash": "abc123", ...}
```

### 3. search_code(repo, pattern, file_pattern=None, max_results=100)
Search code using regex patterns. Returns matches with metadata.

**Examples:**
```python
# Basic search
search_code("react", "useState")

# Search in specific files
search_code("typescript", "interface", file_pattern="*.ts")

# Complex regex
search_code("docs-aspire", "class\\s+\\w+Component")
```

**Tips:**
- Use `file_pattern` to narrow search (e.g., "*.md", "src/**/*.js")
- Check `meta.hint` in response for suggestions when no results
- `meta.search_time_ms` helps gauge query complexity

### 4. read_file(repo, path)
Read file contents. Returns enhanced errors with suggestions.

**Example:**
```python
read_file("react", "packages/react/src/React.js")
# If file not found, suggestions are provided automatically
```

**Error handling:**
- Shows if directory exists but file doesn't
- Suggests similar files in same directory
- Helps identify typos in file paths

### 5. list_files(repo, path="", pattern=None)
List directory contents with file/directory previews.

**Examples:**
```python
# List root directory
list_files("react")

# List specific directory
list_files("react", "packages/react/src")

# Filter with glob pattern
list_files("typescript", "src", pattern="*.ts")
```

**Response includes:**
- `file_count` and `dir_count` for directories
- `preview` showing first 3 items in directories
- File sizes

### 6. tree(repo, path="", depth=2, file_pattern=None)
Get tree view of directory structure.

**Examples:**
```python
# Quick overview (depth=2, default)
tree("react", "packages")

# Deep dive (depth=4)
tree("typescript", "src", depth=4)

# Find all markdown files
tree("docs-aspire", "docs", depth=3, file_pattern="*.md")
```

**Best for:**
- Understanding project layout
- Finding where certain file types live
- Quick navigation planning

### 7. get_readme(repo)
Quick access to repository README.

**Example:**
```python
get_readme("react")
# Returns README.md content
```

## Common Workflows

### Workflow 1: Exploring a New Repository

```python
# Step 1: Check what's available
list_repos()

# Step 2: Get repository info
get_repo_info("react")

# Step 3: See structure
tree("react", depth=2)

# Step 4: Read README for context
get_readme("react")
```

### Workflow 2: Finding Specific Code

```python
# Step 1: Broad search to find relevant files
search_code("typescript", "Parser", file_pattern="*.ts")

# Step 2: Use tree to understand file location context
tree("typescript", "src/compiler", depth=2)

# Step 3: Read the specific file
read_file("typescript", "src/compiler/parser.ts")
```

### Workflow 3: Understanding File Structure

```python
# Step 1: Tree view to see layout
tree("react", "packages/react/src", depth=3)

# Step 2: List specific directory for details
list_files("react", "packages/react/src")

# Step 3: Read files of interest
read_file("react", "packages/react/src/React.js")
```

## Search Tips

### Regex Patterns
- `\\bfunction\\b` - word boundaries for exact matches
- `class.*Component` - flexible matching
- `import.*from` - find import statements
- `\\w+Error` - find all error classes

### File Patterns (glob)
- `*.md` - all markdown files
- `**/*.ts` - all TypeScript files recursively
- `src/**/*.test.js` - all test files in src/
- `*.{ts,tsx}` - multiple extensions

### Performance Tips
- Use `file_pattern` to reduce search scope
- Start with `tree()` to understand structure
- Use smaller `max_results` for faster searches
- Check `search_time_ms` in meta to gauge query cost

## Troubleshooting

### "File not found" errors
- Check the `suggestions` in error message
- Use `tree()` to verify path structure
- Use `list_files()` to see available files

### "No matches found"
- Check `meta.hint` for suggestions
- Try broader search pattern
- Verify file_pattern is correct
- Use `tree()` with file_pattern to confirm files exist

### Large repositories
- Use `file_pattern` to narrow scope
- Start with shallow `tree()` depth
- Use more specific search patterns
- Consider if repo is fully cloned (check `available` in list_repos)

## Best Practices

1. **Start broad, then narrow**: Use tree → list_files → read_file
2. **Use metadata**: Check search_time_ms and file_count to gauge scope
3. **Leverage previews**: directory previews in list_files save time
4. **Pattern matching**: Combine search_code file_pattern with regex for precision
5. **Error messages**: Read them carefully - they contain helpful suggestions

---
Need help? Check: https://github.com/sunnamed434/yarmcp
"""


@mcp.tool()
def tree(
    repo: Annotated[str, Field(description="Repository name")],
    path: Annotated[str, Field(description="Directory path relative to repo root (default: root)")] = "",
    depth: Annotated[int, Field(description="Maximum depth to traverse (1-5, default: 2)")] = 2,
    file_pattern: Annotated[str | None, Field(description="Show only files matching pattern, e.g. '*.md'")] = None,
) -> str:
    """
    Get a tree view of repository directory structure.
    Returns a formatted tree showing directories and files up to specified depth.
    Useful for quick exploration and understanding repository layout.
    """
    validate_repo_name(repo)

    if path:
        full_path = validate_repo_path(repo, path)
    else:
        full_path = get_repo_path(repo)

    if not full_path.exists():
        raise FileNotFoundError(f"Path not found: {path or '/'}")

    if not full_path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    # Limit depth to reasonable range
    depth = max(1, min(5, depth))

    def build_tree(current_path: Path, current_depth: int, prefix: str = "") -> list[str]:
        """Recursively build tree structure."""
        if current_depth > depth:
            return []

        lines = []
        try:
            entries = sorted(current_path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
            # Filter hidden files
            entries = [e for e in entries if not e.name.startswith(".")]

            # Apply file pattern filter if specified
            if file_pattern and current_depth == depth:
                # Only filter files at max depth
                entries = [e for e in entries if e.is_dir() or e.match(file_pattern)]

            for i, entry in enumerate(entries):
                is_last = i == len(entries) - 1
                connector = "└── " if is_last else "├── "
                extension = "    " if is_last else "│   "

                if entry.is_dir():
                    # Count files in directory
                    try:
                        children = list(entry.iterdir())
                        visible_children = [c for c in children if not c.name.startswith(".")]

                        if file_pattern:
                            # Count only matching files
                            file_count = sum(1 for c in visible_children if c.is_file() and c.match(file_pattern))
                        else:
                            file_count = sum(1 for c in visible_children if c.is_file())

                        dir_label = f"{entry.name}/ ({file_count} files)" if file_count > 0 else f"{entry.name}/"
                    except (PermissionError, OSError):
                        dir_label = f"{entry.name}/ (access denied)"

                    lines.append(f"{prefix}{connector}{dir_label}")

                    # Recurse into subdirectory
                    if current_depth < depth:
                        lines.extend(build_tree(entry, current_depth + 1, prefix + extension))
                else:
                    # File
                    if not file_pattern or entry.match(file_pattern):
                        lines.append(f"{prefix}{connector}{entry.name}")

        except (PermissionError, OSError) as e:
            lines.append(f"{prefix}(error: {e})")

        return lines

    # Build tree starting from root
    tree_lines = [f"{full_path.name}/"]
    tree_lines.extend(build_tree(full_path, 1))

    result = "\n".join(tree_lines)

    # Add metadata footer
    footer_parts = [f"\nDepth: {depth}"]
    if file_pattern:
        footer_parts.append(f"Pattern: {file_pattern}")
    result += "".join(footer_parts)

    return result


# Health check endpoint (handled by FastMCP's HTTP server)
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse({"status": "healthy", "service": "yarmcp"})


# =============================================================================
# OAuth 2.1 Endpoints
# =============================================================================

@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource(request):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
    issuer = get_issuer_url(request)

    return JSONResponse({
        "resource": issuer,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
        "resource_documentation": "https://github.com/sunnamed434/yarmcp",
    })


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    issuer = get_issuer_url(request)

    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }

    # Add registration endpoint if DCR is enabled
    if settings.oauth_allow_dcr:
        metadata["registration_endpoint"] = f"{issuer}/oauth/register"

    return JSONResponse(metadata)


@mcp.custom_route("/.well-known/jwks.json", methods=["GET"])
async def oauth_jwks(request):
    """JSON Web Key Set endpoint for JWT verification."""
    issuer = get_issuer_url(request)
    jwt_mgr = get_jwt_manager(issuer)
    return JSONResponse(jwt_mgr.get_jwks())


@mcp.custom_route("/oauth/register", methods=["POST"])
async def oauth_register(request):
    """Dynamic Client Registration (RFC 7591)."""
    if not settings.oauth_allow_dcr:
        return JSONResponse(
            status_code=403,
            content={"error": "registration_not_supported"}
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Invalid JSON body"}
        )

    # Required fields
    client_name = body.get("client_name", "Unknown Client")
    redirect_uris = body.get("redirect_uris", [])

    if not redirect_uris:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "redirect_uris is required"}
        )

    # Optional fields
    grant_types = body.get("grant_types", ["authorization_code"])
    response_types = body.get("response_types", ["code"])

    # Register the client
    storage = get_client_storage()
    client = storage.register_client(
        client_name=client_name,
        redirect_uris=redirect_uris,
        grant_types=grant_types,
        response_types=response_types,
    )

    if client is None:
        return JSONResponse(
            status_code=503,
            content={"error": "temporarily_unavailable", "error_description": "Maximum clients reached"}
        )

    return JSONResponse({
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "token_endpoint_auth_method": "client_secret_basic",
    }, status_code=201)


@mcp.custom_route("/oauth/authorize", methods=["GET", "POST"])
async def oauth_authorize(request):
    """OAuth 2.1 Authorization Endpoint."""
    issuer = get_issuer_url(request)

    if request.method == "GET":
        # Parse authorization request
        params = dict(request.query_params)

        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        response_type = params.get("response_type")
        state = params.get("state", "")
        scope = params.get("scope", "mcp:read")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "S256")

        # Validate required parameters
        if not client_id:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "client_id is required"}
            )

        if response_type != "code":
            return JSONResponse(
                status_code=400,
                content={"error": "unsupported_response_type"}
            )

        if not redirect_uri:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "redirect_uri is required"}
            )

        # PKCE is required for MCP
        if not code_challenge:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code_challenge is required (PKCE)"}
            )

        if code_challenge_method != "S256":
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Only S256 code_challenge_method is supported"}
            )

        if not is_valid_challenge(code_challenge):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Invalid code_challenge format"}
            )

        # Verify client exists
        storage = get_client_storage()
        client = storage.get_client(client_id)
        if not client:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_client", "error_description": "Unknown client_id"}
            )

        # Verify redirect_uri against allowed patterns
        if not validate_redirect_uri(redirect_uri, client.redirect_uris):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Invalid redirect_uri"}
            )

        # Show consent page
        return HTMLResponse(get_consent_page(
            client_name=client.client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            password_required=bool(settings.oauth_authorize_password),
        ))

    elif request.method == "POST":
        # Handle consent form submission
        form = await request.form()

        action = form.get("action")
        client_id = form.get("client_id")
        redirect_uri = form.get("redirect_uri")
        state = form.get("state", "")
        scope = form.get("scope", "mcp:read")
        code_challenge = form.get("code_challenge")
        code_challenge_method = form.get("code_challenge_method", "S256")
        password = form.get("password", "")

        # Validate password if required
        if settings.oauth_authorize_password:
            if not secrets.compare_digest(password, settings.oauth_authorize_password):
                return HTMLResponse(get_consent_page(
                    client_name="Client",
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    state=state,
                    scope=scope,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    password_required=True,
                    error="Invalid password",
                ))

        if action == "deny":
            # User denied access
            error_params = urlencode({"error": "access_denied", "state": state})
            return RedirectResponse(
                url=f"{redirect_uri}?{error_params}",
                status_code=302
            )

        # Generate authorization code
        code = generate_authorization_code()

        # Store authorization code data
        auth_data = AuthCodeData(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            created_at=__import__("time").time(),
        )
        _auth_codes.set(code, auth_data)

        # Redirect back to client with code
        callback_params = urlencode({"code": code, "state": state})
        return RedirectResponse(
            url=f"{redirect_uri}?{callback_params}",
            status_code=302
        )


@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token(request):
    """OAuth 2.1 Token Endpoint."""
    issuer = get_issuer_url(request)
    jwt_mgr = get_jwt_manager(issuer)
    storage = get_client_storage()

    # Parse request body (supports both form and JSON)
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request"}
            )
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type")

    # Extract client credentials (from body or Basic auth header)
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            pass

    # Handle different grant types
    if grant_type == "client_credentials":
        # Client Credentials Grant
        if not client_id or not client_secret:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client"}
            )

        if not storage.verify_client(client_id, client_secret):
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client"}
            )

        scope = body.get("scope", "mcp:read")

        token, expires_in = jwt_mgr.generate_access_token(
            client_id=client_id,
            audience=issuer,
            scope=scope,
        )

        return JSONResponse({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": scope,
        })

    elif grant_type == "authorization_code":
        # Authorization Code Grant
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        code_verifier = body.get("code_verifier")

        if not code:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code is required"}
            )

        # Retrieve and remove authorization code (one-time use)
        auth_data = _auth_codes.pop(code)
        if not auth_data:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
            )

        # Verify client
        if client_id and auth_data.client_id != client_id:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "client_id mismatch"}
            )

        # Verify redirect_uri
        if redirect_uri and auth_data.redirect_uri != redirect_uri:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "redirect_uri mismatch"}
            )

        # Verify PKCE
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code_verifier is required"}
            )

        if not verify_code_challenge(code_verifier, auth_data.code_challenge, auth_data.code_challenge_method):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid code_verifier"}
            )

        # Generate access token
        token, expires_in = jwt_mgr.generate_access_token(
            client_id=auth_data.client_id,
            audience=issuer,
            scope=auth_data.scope,
        )

        return JSONResponse({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": auth_data.scope,
        })

    else:
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type"}
        )


def get_consent_page(
    client_name: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str,
    password_required: bool = False,
    error: str = "",
) -> str:
    """Generate the OAuth consent page HTML."""
    scopes_list = scope.split() if scope else ["mcp:read"]
    scopes_html = "".join(f"<li>{s}</li>" for s in scopes_list)

    error_html = f'<div class="error">{error}</div>' if error else ""

    password_field = ""
    if password_required:
        password_field = '''
        <div class="field">
            <label for="password">Authorization Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        '''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorize - YARMCP</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 440px;
            width: 100%;
            padding: 40px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 24px;
        }}
        .logo h1 {{
            font-size: 28px;
            color: #1a1a2e;
            font-weight: 700;
        }}
        .logo span {{
            color: #4f46e5;
        }}
        h2 {{
            font-size: 18px;
            color: #374151;
            margin-bottom: 16px;
            text-align: center;
        }}
        .client-name {{
            font-weight: 600;
            color: #4f46e5;
        }}
        .scopes {{
            background: #f3f4f6;
            border-radius: 8px;
            padding: 16px;
            margin: 20px 0;
        }}
        .scopes h3 {{
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 8px;
        }}
        .scopes ul {{
            list-style: none;
            padding-left: 0;
        }}
        .scopes li {{
            padding: 6px 0;
            color: #374151;
            font-size: 14px;
        }}
        .scopes li:before {{
            content: "\\2713";
            color: #10b981;
            margin-right: 8px;
        }}
        .field {{
            margin-bottom: 16px;
        }}
        .field label {{
            display: block;
            font-size: 14px;
            color: #374151;
            margin-bottom: 6px;
        }}
        .field input {{
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 14px;
        }}
        .field input:focus {{
            outline: none;
            border-color: #4f46e5;
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }}
        .buttons {{
            display: flex;
            gap: 12px;
            margin-top: 24px;
        }}
        button {{
            flex: 1;
            padding: 14px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .deny {{
            background: #fff;
            border: 1px solid #d1d5db;
            color: #374151;
        }}
        .deny:hover {{
            background: #f3f4f6;
        }}
        .allow {{
            background: #4f46e5;
            border: none;
            color: #fff;
        }}
        .allow:hover {{
            background: #4338ca;
        }}
        .error {{
            background: #fef2f2;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 14px;
        }}
        .footer {{
            text-align: center;
            margin-top: 24px;
            font-size: 12px;
            color: #9ca3af;
        }}
        .github-link {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-top: 8px;
            color: #6b7280;
            text-decoration: none;
            transition: color 0.2s;
        }}
        .github-link:hover {{
            color: #4f46e5;
        }}
        .github-link svg {{
            width: 16px;
            height: 16px;
            fill: currentColor;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>YAR<span>MCP</span></h1>
        </div>
        <h2><span class="client-name">{client_name}</span> wants to access your YARMCP server</h2>

        {error_html}

        <div class="scopes">
            <h3>This will allow the application to:</h3>
            <ul>
                {scopes_html}
            </ul>
        </div>

        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">

            {password_field}

            <div class="buttons">
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
                <button type="submit" name="action" value="allow" class="allow">Allow</button>
            </div>
        </form>

        <div class="footer">
            YARMCP - Yet Another Repository MCP Server
            <br>
            <a href="https://github.com/sunnamed434/yarmcp" target="_blank" rel="noopener noreferrer" class="github-link">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                </svg>
                Open Source on GitHub
            </a>
        </div>
    </div>
</body>
</html>'''


if __name__ == "__main__":
    import uvicorn

    port = settings.yarmcp_port
    print(f"Starting YARMCP MCP server on port {port}")

    # Run with streamable HTTP transport (stateless mode)
    # Serve at root "/" for Claude.ai compatibility (redirects cause issues)
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        path="/",  # Serve at root - redirects break Claude Desktop
        stateless_http=True,  # Stateless mode - no session management needed
    )
