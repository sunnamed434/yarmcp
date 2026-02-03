# YARMCP Configuration Guide

This folder contains everything you need to self-host YARMCP with Docker Compose.

## What's in this folder

- **[docker-compose.yaml](docker-compose.yaml)** - Main Docker Compose configuration with 2 services:
  - `mcp` - MCP server (port 9742) with OAuth 2.1 support
  - `updater` - Auto-updates repos on schedule (default: every 6 hours)
- **[.env.example](.env.example)** - Environment variables template
- **[repos.yaml.example](repos.yaml.example)** - Repositories configuration template

## Prerequisites

Before you begin, ensure you have:

- **Docker Engine 20.10+** and **Docker Compose 2.0+**
- **openssl** (for generating authentication tokens)
- **10GB+ free disk space** (for repository storage, more if cloning large repos like React/TypeScript)
- **Port 9742 available** (or ability to change ports in docker-compose.yaml)
- **Basic command line knowledge**
- **SSH access to your server** (if deploying remotely)

Check your setup:
```bash
docker --version
docker compose version
openssl version
df -h  # Check available disk space
```

## Quick Setup

### 1. Create directories

Create the required directory structure on your server:

```bash
# Create all required directories
sudo mkdir -p /opt/yarmcp/{config,repos,data,secrets/ssh}

# Set appropriate permissions (optional, adjust user as needed)
sudo chown -R $USER:$USER /opt/yarmcp
```

### 2. Copy files to your server

Copy these files from this example folder to your deployment location:

```bash
# Copy configuration files
cp docker-compose.yaml /opt/yarmcp/docker-compose.yaml
cp .env.example /opt/yarmcp/.env.local
cp repos.yaml.example /opt/yarmcp/repos.yaml.example
```

### 3. Environment Variables

Edit your `.env.local`:

```bash
cd /opt/yarmcp
nano .env.local
```

**Required variables:**

```bash
# Simple Bearer Token Authentication (for Claude Desktop, Claude Code CLI)
# This is the primary authentication method - generate with: openssl rand -hex 32
BEARER_AUTH_TOKEN=your-secure-token-here

# Bind mount paths (absolute paths on your host)
MCP_BINDMOUNT_0=/opt/yarmcp/config      # Config directory (read-only)
MCP_BINDMOUNT_1=/opt/yarmcp/repos       # Repos directory (read-only for MCP)
MCP_BINDMOUNT_2=/opt/yarmcp/data        # Data directory (writable, for OAuth clients storage)
UPDATER_BINDMOUNT_0=/opt/yarmcp/config  # Config directory (read-only)
UPDATER_BINDMOUNT_1=/opt/yarmcp/repos   # Repos directory (read-write for updater)
UPDATER_BINDMOUNT_2=/opt/yarmcp/secrets/ssh  # SSH keys (optional, for private repos)

# GitHub token for private repos (optional, leave empty for public repos only)
GITHUB_TOKEN=

# Update schedule (cron format)
UPDATE_SCHEDULE=0 */6 * * *  # Default: every 6 hours

# OAuth 2.1 settings (for Claude.ai web, ChatGPT, Cursor, etc.)
OAUTH_CLIENT_ID=my-yarmcp-client
OAUTH_CLIENT_SECRET=your-oauth-secret-here    # generate with: openssl rand -hex 32
OAUTH_JWT_SECRET=your-jwt-signing-secret-here # generate with: openssl rand -hex 32 - must be different from CLIENT_SECRET
OAUTH_TOKEN_EXPIRY=2592000  # Access token lifetime in seconds (default: 30 days)
```

#### Authentication Methods Explained

YARMCP supports two authentication methods:

**Method 1: Simple Bearer Token (Recommended for most users)**
- Uses `BEARER_AUTH_TOKEN` environment variable
- Client sends: `Authorization: Bearer <token>` header
- Best for: Claude Desktop, Claude Code CLI, any direct API access
- Setup: Just generate one random token with `openssl rand -hex 32`

**Method 2: OAuth 2.1 (For Claude.ai web and advanced integrations)**
- Uses `OAUTH_CLIENT_SECRET` + `OAUTH_JWT_SECRET` + `OAUTH_CLIENT_ID`
- Client goes through OAuth authorization flow
- Best for: Claude.ai web browser, ChatGPT, Cursor with OAuth support
- CRITICAL: `OAUTH_JWT_SECRET` must be set and persist across container restarts
  - If empty, a new secret is generated each restart → existing tokens become invalid
  - Users get logged out after every restart

**Which should I use?**
- Use Method 1 (BEARER_AUTH_TOKEN) for local development and CLI tools
- Use Method 2 (OAuth) only if you need Claude.ai web browser access
- You can use both simultaneously - clients choose which method to use

### 4. Repositories Configuration

Create `/opt/yarmcp/config/repos.yaml` from the template:

```bash
# Copy template
cp repos.yaml.example /opt/yarmcp/config/repos.yaml

# Edit with your repos
nano /opt/yarmcp/config/repos.yaml
```

**Example `repos.yaml`:**

```yaml
repos:
  # Using default branch
  - name: react
    url: https://github.com/facebook/react.git
    auto_update: true

  # Using specific branch
  - name: typescript
    url: https://github.com/microsoft/TypeScript.git
    branch: main
    auto_update: true
    description: TypeScript compiler and language service
```

**Fields:**
- `name` - Unique identifier, used as directory name (required)
- `url` - Git clone URL (HTTPS or SSH) (required)
- `branch` - (Optional) Specific branch to track. Omit to use repository's default branch. If specified branch doesn't exist, will show error with available branches.
- `auto_update` - Auto-pull updates on schedule (optional, default: true)
- `description` - Human-readable description (optional)

### 5. Private Repos (Optional)

**Option A: GitHub PAT** (easier)
```bash
# Add to .env.local
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

**Option B: SSH Keys**
```bash
# Generate key
mkdir -p /opt/yarmcp/secrets/ssh
ssh-keygen -t ed25519 -f /opt/yarmcp/secrets/ssh/id_ed25519 -N ""

# Set correct permissions (SSH requires this)
chmod 600 /opt/yarmcp/secrets/ssh/id_ed25519
chmod 644 /opt/yarmcp/secrets/ssh/id_ed25519.pub

# Add to GitHub (Settings → SSH Keys)
cat /opt/yarmcp/secrets/ssh/id_ed25519.pub

# Use SSH URLs in repos.yaml
- name: private-repo
  url: git@github.com:user/private-repo.git
```

### 6. Run

```bash
cd /opt/yarmcp
docker compose --env-file .env.local up -d
```

### 7. Test local access

```bash
curl http://localhost:9742/health
# Should return: {"status":"ok"}
```

## Expose to Internet (Optional)

**When do you need this?**

- ✅ **You need public access if:**
  - Using Claude.ai web, ChatGPT, or Cursor (requires HTTPS URL)
  - Using OAuth 2.1 authentication (requires TLS)
  - Accessing from multiple locations/devices

- ❌ **You DON'T need this if:**
  - Only using Claude Code CLI on the same machine (localhost works)
  - Only using Claude Code CLI with SSH port forwarding

### Recommended: Cloudflare Zero Trust Tunnel

**Why Cloudflare Tunnel?**
- ✅ Free for personal use
- ✅ Automatic SSL/TLS certificates (no Let's Encrypt setup)
- ✅ No need to open firewall ports
- ✅ No need for reverse proxy (Nginx/Caddy)
- ✅ Built-in access control and DDoS protection

**Setup steps:**

1. **Install cloudflared** (on your server):
```bash
# Debian/Ubuntu
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Or using docker
docker pull cloudflare/cloudflared:latest
```

2. **Authenticate with Cloudflare**:
```bash
cloudflared tunnel login
```

3. **Create a tunnel**:
```bash
cloudflared tunnel create yarmcp
# Save the Tunnel ID shown
```

4. **Configure the tunnel** (`~/.cloudflared/config.yml`):
```yaml
tunnel: <YOUR-TUNNEL-ID>
credentials-file: /root/.cloudflared/<YOUR-TUNNEL-ID>.json

ingress:
  - hostname: yarmcp.yourdomain.com
    service: http://localhost:9742
  - service: http_status:404
```

5. **Add DNS record**:
```bash
cloudflared tunnel route dns yarmcp yarmcp.yourdomain.com
```

6. **Run the tunnel**:
```bash
cloudflared tunnel run yarmcp
```

**Or with Docker** (if YARMCP is in different docker network):

Create `docker-compose.override.yaml` in `/opt/yarmcp/`:

```yaml
services:
  mcp:
    networks:
      - yarmcp-network
      - cloudflared_network  # Your cloudflared network

networks:
  cloudflared_network:
    external: true
```

Then configure cloudflared to connect to `mcp:9742`.

**Result:** Access YARMCP at `https://yarmcp.yourdomain.com`

### Alternative: Nginx + Let's Encrypt

<details>
<summary>Click to expand for Nginx reverse proxy setup</summary>

If you prefer traditional reverse proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name yarmcp.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:9742;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use Certbot for Let's Encrypt certificates:
```bash
sudo certbot --nginx -d yarmcp.yourdomain.com
```

</details>

## Directory Structure

```
/opt/yarmcp/
├── config/
│   └── repos.yaml          # Your repositories
├── repos/                  # Cloned repos (auto-created)
│   ├── react/
│   ├── typescript/
│   └── ...
└── secrets/
    └── ssh/                # SSH keys (optional)
        ├── id_ed25519
        └── id_ed25519.pub
```

## Connect to AI Provider

YARMCP supports **OAuth 2.1** for web-based AI interfaces and **Bearer tokens** for CLI tools.

### Claude.ai Web / ChatGPT / Cursor (OAuth)

1. Go to your AI provider's connector settings
2. Add a custom MCP connector with:
   - **URL:** `https://your-yarmcp-domain.com`
   - **Client ID:** Your `OAUTH_CLIENT_ID` from `.env.local`
   - **Client Secret:** Your `OAUTH_CLIENT_SECRET` from `.env.local`

**Supported platforms:**
- Claude.ai (Pro/Max) - Settings → Connectors → Add custom connector
- ChatGPT (Developer Mode) - Settings → Apps → Add MCP server
- Cursor - Settings → MCP → Add server
- GitHub Copilot - Uses Dynamic Client Registration (DCR)

### Claude Code CLI (Bearer Token)

```bash
claude mcp add --transport http yarmcp https://your-yarmcp-url.com --header "Authorization: Bearer your-auth-token-here"
```

Verify connection:
```bash
claude mcp list
```

### OAuth Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OAUTH_ENABLED` | No | `true` | Enable OAuth 2.1 support |
| `OAUTH_CLIENT_ID` | Yes* | - | Pre-configured OAuth client ID |
| `OAUTH_CLIENT_SECRET` | Yes* | - | Pre-configured OAuth client secret |
| `OAUTH_ALLOW_DCR` | No | `true` | Allow Dynamic Client Registration |
| `OAUTH_AUTHORIZE_PASSWORD` | No | - | Password for consent screen (optional) |
| `OAUTH_TOKEN_EXPIRY` | No | `2592000` | Access token lifetime in seconds (default: 30 days) |

*Required for Claude.ai/ChatGPT/Cursor. Not needed if only using CLI with Bearer token.

### Cloudflare Tunnel Setup (Optional)

<details>
<summary>Click to expand if you use Cloudflare Zero Trust Tunnel</summary>

**Problem:** Cloudflare Tunnel can't reach YARMCP by default (different Docker networks).

**Solution:** Add one file, restart, configure tunnel.

**1. Create `docker-compose.override.yaml` in `/opt/yarmcp/`:**

```yaml
services:
  mcp:
    networks:
      - global_network  # Replace with your tunnel's network name
      - yarmcp-network

networks:
  global_network:
    external: true
```

**2. Restart:**
```bash
docker compose down && docker compose up -d
```

**3. Cloudflare Tunnel settings:**
- URL: `mcp:9742`
- Path: (empty)

Done! Access at `https://yarmcp.your-domain.com/mcp`

</details>

### Claude Code Example

```bash
claude mcp add --transport http yarmcp https://your-yarmcp-url.com --header "Authorization: Bearer your-auth-token-here"
```

Verify connection:
```bash
claude mcp list
```

## AI Documentation Integration

**YARMCP only works if AI knows to use it.**

### Setup (2 steps)

**1. Add to your project's CLAUDE.md (or AI.md):**

Add this section:

```markdown
## YARMCP - Library Source Code

**CRITICAL: AI training data is ~1 year outdated. Always verify external library APIs with YARMCP before implementing.**

This project uses YARMCP to access current source code of external libraries, avoiding outdated assumptions.

### Quick Reference

Available MCP tools:
- `mcp__yarmcp__list_repos()` - List all configured repos
- `mcp__yarmcp__get_repo_info(repo)` - Get repo metadata + last commit
- `mcp__yarmcp__search_code(repo, pattern)` - Search code (ripgrep regex)
- `mcp__yarmcp__read_file(repo, path)` - Read file content
- `mcp__yarmcp__list_files(repo, path?)` - List directory contents
- `mcp__yarmcp__tree(repo, path?, depth?, pattern?)` - Formatted directory tree view
- `mcp__yarmcp__get_readme(repo)` - Quick README access
- `mcp__yarmcp__get_yarmcp_usage_guide()` - Built-in documentation with usage patterns

### When to Read yarmcp/CLAUDE.md

Read [yarmcp/CLAUDE.md](yarmcp/CLAUDE.md) if you need to:
- **Plan an implementation** involving multiple external libraries (see Workflow 3)
- **Verify an API** you found via web search to ensure it matches current code (see Workflow 2)
- **Optimize searches** for large repos (React, TypeScript, .NET, etc.)
- **Understand search strategies** and repo navigation patterns

### Basic Pattern

Before implementing a feature using external libraries:

1. **Check what's available**: `mcp__yarmcp__list_repos()` - see if library is configured
2. **Search for patterns**: `mcp__yarmcp__search_code(repo, "pattern")` - find relevant code
3. **Read files**: `mcp__yarmcp__read_file(repo, "path")` - examine actual implementation
4. **Implement based on current code** - not training data assumptions

**If library NOT in YARMCP:** Offer to add the library to YARMCP for accuracy, or proceed with training data noting it may be 1+ year outdated.
```

**2. Create `yarmcp/CLAUDE.md` in your project:**

Copy and customize the template from this example:
- Copy `example/AI.md.example`
- Save as `yarmcp/CLAUDE.md` in your project root
- Customize with your YARMCP repos and conventions
- (Optional) Add a "Configured Repos" section listing what's available in your YARMCP instance

That's it. AI will auto-load this context and use YARMCP for all external library questions.

**Why separate files?**
- `CLAUDE.md` (main) - Brief reference with link to detailed workflows
- `yarmcp/CLAUDE.md` - Detailed workflows, search strategies, best practices
  - AI reads main file on every task (lightweight context)
  - AI reads detailed file only when planning complex features or optimizing searches
  - Keeps token usage efficient while ensuring comprehensive guidance when needed

## Updates

Repos auto-update every 6 hours. Force update:

```bash
docker compose --env-file .env.local restart updater
```
