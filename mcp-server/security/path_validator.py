import os
import re
from pathlib import Path

from config import settings, get_repo_path


class PathTraversalError(Exception):
    """Raised when a path traversal attack is detected."""
    pass


class InvalidRepoNameError(Exception):
    """Raised when an invalid repository name is provided."""
    pass


def validate_repo_name(repo: str) -> str:
    """
    Validate that a repository name is safe.

    Repository names must be lowercase alphanumeric with hyphens only.
    This prevents directory traversal via repo name.
    """
    if not repo:
        raise InvalidRepoNameError("Repository name cannot be empty")

    # Only allow lowercase alphanumeric and hyphens
    if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$", repo):
        raise InvalidRepoNameError(
            f"Invalid repository name: '{repo}'. "
            "Must be lowercase alphanumeric with hyphens only."
        )

    # Additional safety checks
    if ".." in repo or "/" in repo or "\\" in repo:
        raise PathTraversalError("Path traversal attempt detected in repo name")

    return repo


def validate_repo_path(repo: str, path: str) -> Path:
    """
    Validate and resolve a path within a repository.

    Prevents path traversal attacks by ensuring the resolved path
    stays within the repository directory.

    Args:
        repo: Repository name (already validated)
        path: Relative path within the repository

    Returns:
        Resolved absolute Path object

    Raises:
        PathTraversalError: If path escapes repository directory
        FileNotFoundError: If repository doesn't exist
    """
    # Validate repo name first
    validate_repo_name(repo)

    # Get repository base path
    repo_path = get_repo_path(repo)

    if not repo_path.exists():
        raise FileNotFoundError(f"Repository '{repo}' not found (not cloned)")

    # Resolve the repo path to absolute
    repo_path = repo_path.resolve()

    # Normalize and resolve the requested path
    # First, join with repo path
    requested_path = (repo_path / path).resolve()

    # CRITICAL: Verify the resolved path is under the repo directory
    try:
        requested_path.relative_to(repo_path)
    except ValueError:
        raise PathTraversalError(
            f"Path traversal detected: '{path}' escapes repository directory"
        )

    # Additional check: the string representation must start with repo path
    # This catches edge cases with symlinks
    if not str(requested_path).startswith(str(repo_path) + os.sep) and requested_path != repo_path:
        raise PathTraversalError(
            f"Path traversal detected: '{path}' resolves outside repository"
        )

    # Check for symlinks that escape the repository
    if requested_path.is_symlink():
        link_target = requested_path.resolve()
        try:
            link_target.relative_to(repo_path)
        except ValueError:
            raise PathTraversalError(
                f"Symlink escape detected: '{path}' points outside repository"
            )

    return requested_path


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is safe (no path components).
    """
    # Reject any path separators
    if "/" in filename or "\\" in filename:
        return False

    # Reject parent directory references
    if filename == ".." or filename.startswith(".."):
        return False

    # Reject hidden files that might be sensitive
    sensitive_patterns = [".git", ".env", ".ssh", ".config"]
    if any(filename.lower().startswith(p) for p in sensitive_patterns):
        return False

    return True
