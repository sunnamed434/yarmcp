# YARMCP

**Y**et **A**nother **R**epo **MCP** - Self-hosted MCP server that clones git repos to your server, giving AI assistants fast access to up-to-date source code without hitting GitHub API limits or needing multiple repo clones per project.

[![Docker Pulls](https://img.shields.io/docker/pulls/sunnamed434/yarmcp-mcp)](https://hub.docker.com/r/sunnamed434/yarmcp-mcp)
[![Docker Image Size](https://img.shields.io/docker/image-size/sunnamed434/yarmcp-mcp/latest)](https://hub.docker.com/r/sunnamed434/yarmcp-mcp)
[![Docker Image Version](https://img.shields.io/docker/v/sunnamed434/yarmcp-mcp)](https://hub.docker.com/r/sunnamed434/yarmcp-mcp)
[![GHCR](https://ghcr-badge.egpl.dev/sunnamed434/yarmcp-mcp/latest_tag?trim=major&label=GHCR&ignore=edge,dev)](https://github.com/sunnamed434/yarmcp/pkgs/container/yarmcp-mcp)

## Use Cases

**You're using AI (Claude Code, Cursor, Claude.ai web, ChatGPT, Copilot, etc.) and want to ask:** "How does the latest React Router v7 handle data loading?"
- ❌ AI training data is 6-7 months old - suggests outdated APIs or does web search (slow, eats tokens, not always accurate)
- ❌ GitHub MCP works but hits 5,000 requests/hour limit fast
- ✅ YARMCP: Direct server access, no rate limits, always up-to-date, no web search needed

**You work with 10+ repos (React, TypeScript, TailwindCSS, etc.) and hit rate limits:**
- ❌ GitHub MCP: 5,000 requests/hour shared - runs out fast
- ❌ git-mcp: Still hits GitHub API limits
- ✅ YARMCP: Zero rate limits, reads from server storage

**You want AI to reference official source code across projects:**

Option 1: Create `/repos` folder on your PC with all clones
- ❌ 10 repos × 500MB = 5GB disk space
- ❌ Must manually `git pull` to keep updated
- ❌ Switching PCs? Start over or setup server sync

Option 2: Clone repos into your project directory
- ❌ Your `.git` folder grows massive (GitHub may reject push if too large)
- ❌ Add to `.gitignore`? Each team member must manually clone those repos locally
- ❌ Different versions across team members - no consistency

Option 3: Use YARMCP
- ✅ One server, all projects access same repos (no duplication)
- ✅ Auto-updates every 6 hours (configurable)
- ✅ Shallow clones (`--depth=1`) save 30-95% space depending on repo history
- ✅ Works from any PC, browser, or IDE - just connect to your server
- ✅ Supports private repos (GitHub PAT or SSH keys)

## What Makes YARMCP Different?

**Smart error handling:**
- **File not found suggestions** - Shows similar files when path doesn't exist
- **Directory preview** - First 3 items shown to reduce exploration steps
- **Tree view tool** - Formatted directory trees with Unicode, depth control (1-5 levels)

**Performance & security:**
- **No rate limits** - Server stores cloned repos, no GitHub API calls needed
- **Private repos support** - GitHub PAT or SSH keys for private repositories
- **OAuth 2.1 + PKCE** - Full OAuth flow with dynamic client registration
- **Path validation** - Prevents directory traversal, blocks sensitive files
- **Shallow clones** - `--depth=1` saves disk space and clone time

**AI assistant features:**
- **Usage guide tool** - Built-in `get_yarmcp_usage_guide()` with workflows
- **Ripgrep search** - Fast code search with context lines, performance metrics
- **Per-repo control** - Disable auto-updates for specific repos (frozen versions)

## Alternatives

| Solution | Setup | Tools | Private Repos | File Suggestions | Rate Limits | Best For |
|----------|-------|-------|---------------|-----------------|-------------|----------|
| **YARMCP** | Docker | 8 tools | ✓ PAT/SSH | ✓ Yes | None | Any AI client, private repos, teams |
| **GitHub MCP** | Docker/Cloud | 51 tools | ✓ PAT/OAuth | ✗ No | 5,000/hour | GitHub platform features |
| **git-mcp** | Zero setup | 4 tools | ✗ Public only | ✗ No | GitHub API | Quick public repo docs |
| **git-mcp-server** | npm/bun | 27 tools | ✓ JWT/OAuth | ✗ No | None | Full Git operations |
| **Local clones** | Manual | N/A | ✓ Manual | N/A | None | Single project |

## Quick Start

**For self-hosting**: See [example/README.md](example/README.md) for complete Docker Compose setup guide.

**Private repositories**: Supports GitHub PAT (environment variable) or SSH keys (mount volume). Details in [example/README.md](example/README.md#5-private-repos-optional).

## Docker Image Tags & Versioning

YARMCP uses [Semantic Versioning](https://semver.org/). **For production, pin to a specific version** (e.g., `:1.0.0`) for stability. For testing use `:edge`.

**Images available on:**
- 🐳 **Docker Hub**: `sunnamed434/yarmcp-mcp` (recommended, easier to use)
- 🐙 **GitHub Container Registry** (GHCR): `ghcr.io/sunnamed434/yarmcp-mcp` (also available)

See [releases page](https://github.com/sunnamed434/yarmcp/releases) for available versions.

<details>
<summary><b>📦 Available Docker Tags (click to expand)</b></summary>

### Stable Releases (Recommended for Production)

```bash
# Docker Hub (recommended, simpler syntax)
sunnamed434/yarmcp-mcp:1.0.0         # ✅ Specific version (recommended, immutable)
sunnamed434/yarmcp-mcp:1.0           # Latest patch in 1.0.x (auto-updates patches)
sunnamed434/yarmcp-mcp:1             # Latest minor in 1.x.x (auto-updates)
sunnamed434/yarmcp-mcp:latest        # Latest stable (not recommended for production)
sunnamed434/yarmcp-mcp:stable        # Alias for latest stable

# GitHub Container Registry (also available)
ghcr.io/sunnamed434/yarmcp-mcp:1.0.0      # Same images via GHCR
```

**When to use:**
- **Production**: Use specific version (`:1.0.0`) for predictable behavior
- **Testing**: Use `:latest` or `:1.0` to test updates before pinning
- **Development**: Use `:edge` for latest changes

### Pre-Release Versions (Testing)

```bash
sunnamed434/yarmcp-mcp:0.1.0-alpha.1   # Alpha releases (experimental)
sunnamed434/yarmcp-mcp:0.1.0-beta.1    # Beta releases (feature complete)
sunnamed434/yarmcp-mcp:0.1.0-rc.1      # Release candidates
```

**When to use:**
- Testing new features before stable release
- Helping with bug reports
- Early adopters

### Development Builds (Unstable)

```bash
sunnamed434/yarmcp-mcp:edge            # Latest commit from main branch
sunnamed434/yarmcp-mcp:dev             # Same as edge
sunnamed434/yarmcp-mcp:20260203-abc1234  # Specific dev build (date-SHA)
```

**When to use:**
- Contributing to development
- Testing unreleased features
- Reporting bugs on main branch

**⚠️ Warning:** Dev builds may contain breaking changes or bugs. Not recommended for production.

### Version Format

- **Stable releases**: `MAJOR.MINOR.PATCH` (e.g., `1.2.3`)
- **Pre-releases**: `MAJOR.MINOR.PATCH-TYPE.NUMBER` (e.g., `0.1.0-alpha.1`)
- **Dev builds**: `YYYYMMDD-SHORTHASH` (e.g., `20260203-a1b2c3d`)

</details>

## Development

### Local development

For contributors and local testing, use Docker Compose:

```bash
cd example
docker compose up
```

See [example/README.md](example/README.md) for complete setup instructions.

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_repos()` | List all configured repositories with status |
| `get_repo_info(repo)` | Get repo metadata + last commit info |
| `read_file(repo, path)` | Read file with smart "did you mean" suggestions on errors |
| `search_code(repo, pattern, ...)` | ripgrep code search with context lines and metrics |
| `list_files(repo, path?, pattern?)` | List directory contents with preview (first 3 items) |
| `tree(repo, path?, depth?, pattern?)` | Formatted directory tree view (1-5 levels) |
| `get_readme(repo)` | Quick README access (checks multiple variations) |
| `get_yarmcp_usage_guide()` | Built-in documentation with usage patterns |

## Architecture

```
┌─────────────┐     ┌─────────────┐
│  MCP Server │◄────│   Updater   │
│  (FastMCP)  │     │  (cron git) │
│  Port 9742  │     │             │
└──────┬──────┘     └──────┬──────┘
       │                   │
       ▼                   ▼
   /opt/yarmcp/repos (shared volume)
```

- **MCP Server**: OAuth 2.1 + bearer auth, read-only repo access, serves MCP tools
- **Updater**: Clones new repos, pulls updates on schedule (default: every 6 hours)
