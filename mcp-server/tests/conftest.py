"""
Pytest configuration and fixtures for YARMCP tests.
"""
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import pytest


@pytest.fixture
def temp_repos_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test repositories."""
    temp_dir = Path(tempfile.mkdtemp())
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sample_repo(temp_repos_dir: Path) -> Path:
    """Create a sample repository structure for testing."""
    repo_path = temp_repos_dir / "test-repo"
    repo_path.mkdir(parents=True)

    # Create some sample files
    (repo_path / "README.md").write_text("# Test Repository\n\nThis is a test.")
    (repo_path / "src").mkdir()
    (repo_path / "src" / "main.py").write_text("print('Hello, World!')\n")
    (repo_path / "src" / "utils.py").write_text("def add(a, b):\n    return a + b\n")
    (repo_path / ".git").mkdir()  # Mock git directory

    return repo_path


@pytest.fixture
def malicious_repo(temp_repos_dir: Path) -> Path:
    """Create a repository with malicious content (symlinks, path traversal attempts)."""
    repo_path = temp_repos_dir / "malicious-repo"
    repo_path.mkdir(parents=True)

    # Create a symlink that points outside the repo
    outside_target = temp_repos_dir / "outside-repo-secret.txt"
    outside_target.write_text("SECRET DATA")

    symlink = repo_path / "escape_link"
    symlink.symlink_to(outside_target)

    # Create a file with path traversal in name (should be rejected by validation)
    # Note: This won't actually escape due to filesystem restrictions,
    # but tests validate_repo_path catches it
    (repo_path / "normal.txt").write_text("Normal file")

    return repo_path


@pytest.fixture
def oauth_test_config() -> dict:
    """OAuth configuration for testing."""
    return {
        "client_id": "test_client_id",
        "client_secret": "test_client_secret_32chars_long_12345",
        "jwt_secret": "test_jwt_secret_minimum_32_characters_for_security",
        "issuer": "https://test.yarmcp.example.com",
        "token_expiry": 3600,
    }
