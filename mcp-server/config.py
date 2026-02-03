import os
from pathlib import Path
from datetime import datetime
import yaml
from pydantic import BaseModel, ConfigDict
from pydantic_settings import BaseSettings


class RepoConfig(BaseModel):
    name: str
    url: str
    branch: str = "main"
    private: bool = False
    auto_update: bool = True
    description: str = ""


class ReposConfig(BaseModel):
    repos: list[RepoConfig]
    update_schedule: str = "0 */6 * * *"


class Settings(BaseSettings):
    yarmcp_port: int = 9742
    yarmcp_auth_token: str = ""
    repos_base_path: Path = Path("/opt/yarmcp/repos")
    config_path: Path = Path("/opt/yarmcp/config/repos.yaml")

    # OAuth 2.1 settings
    oauth_enabled: bool = True
    oauth_issuer: str = ""  # Auto-detected from request if empty
    oauth_client_id: str = ""  # Pre-configured client ID
    oauth_client_secret: str = ""  # Pre-configured client secret
    oauth_jwt_secret: str = ""  # Secret for signing JWTs (auto-generated if empty)
    oauth_token_expiry: int = 2592000  # Access token lifetime in seconds (30 days)
    oauth_auth_code_expiry: int = 600  # Auth code lifetime in seconds (10 minutes)
    oauth_allow_dcr: bool = True  # Allow Dynamic Client Registration
    oauth_dcr_max_clients: int = 100  # Maximum number of DCR clients
    oauth_clients_file: Path = Path("/opt/yarmcp/data/oauth_clients.json")
    oauth_authorize_password: str = ""  # Optional password for consent screen
    oauth_allowed_redirect_domains: str = "*"  # Comma-separated list of allowed redirect domains (use "*" to allow any)

    model_config = ConfigDict(
        env_prefix="",
        case_sensitive=False,
    )


settings = Settings()


def load_repos_config() -> ReposConfig:
    """Load repository configuration from repos.yaml."""
    if not settings.config_path.exists():
        return ReposConfig(repos=[])

    with open(settings.config_path) as f:
        data = yaml.safe_load(f)

    return ReposConfig(**data)


def get_repo_path(repo_name: str) -> Path:
    """Get the filesystem path for a repository."""
    return settings.repos_base_path / repo_name


def get_repo_last_updated(repo_name: str) -> str | None:
    """Get the last updated timestamp for a repository from git log."""
    repo_path = get_repo_path(repo_name)
    git_head = repo_path / ".git" / "HEAD"

    if not git_head.exists():
        return None

    # Get modification time of .git/FETCH_HEAD or .git/HEAD
    fetch_head = repo_path / ".git" / "FETCH_HEAD"
    if fetch_head.exists():
        mtime = fetch_head.stat().st_mtime
    else:
        mtime = git_head.stat().st_mtime

    return datetime.fromtimestamp(mtime).isoformat()


def get_repo_commit_hash(repo_name: str) -> str | None:
    """Get the current commit hash for a repository."""
    repo_path = get_repo_path(repo_name)
    head_file = repo_path / ".git" / "HEAD"

    if not head_file.exists():
        return None

    head_content = head_file.read_text().strip()

    # HEAD might be a direct commit hash or a ref
    if head_content.startswith("ref: "):
        ref_path = repo_path / ".git" / head_content[5:]
        if ref_path.exists():
            return ref_path.read_text().strip()[:12]

    return head_content[:12]
