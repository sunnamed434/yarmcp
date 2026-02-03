"""
Security tests for path validation and traversal protection.

These tests verify that YARMCP is protected against:
- Path traversal attacks (../, absolute paths)
- Symlink escape attacks
- Malicious repository names
"""
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.path_validator import (
    validate_repo_name,
    validate_repo_path,
    is_safe_filename,
    PathTraversalError,
    InvalidRepoNameError,
)


class TestRepoNameValidation:
    """Test repository name validation."""

    def test_valid_repo_names(self):
        """Valid repository names should pass validation."""
        valid_names = [
            "react",
            "my-project",
            "test-repo-123",
            "a",
            "project-1",
            "my-awesome-repo",
        ]
        for name in valid_names:
            assert validate_repo_name(name) == name

    def test_invalid_repo_names(self):
        """Invalid repository names should raise InvalidRepoNameError."""
        invalid_names = [
            "",  # Empty
            "My-Project",  # Uppercase
            "project_name",  # Underscore
            "project.name",  # Dot
            "../escape",  # Path traversal
            "project/subdir",  # Slash
            "project\\subdir",  # Backslash
            "-start-dash",  # Starts with dash
            "end-dash-",  # Ends with dash
            "pro ject",  # Space
            "pro@ject",  # Special char
        ]
        for name in invalid_names:
            with pytest.raises((InvalidRepoNameError, PathTraversalError)):
                validate_repo_name(name)

    def test_path_traversal_in_repo_name(self):
        """Path traversal attempts in repo name should be rejected."""
        with pytest.raises(PathTraversalError):
            validate_repo_name("../etc/passwd")

        with pytest.raises(PathTraversalError):
            validate_repo_name("../../secret")


class TestRepoPathValidation:
    """Test path validation within repositories."""

    def test_valid_paths(self, sample_repo: Path, temp_repos_dir: Path, monkeypatch):
        """Valid paths within repository should be allowed."""
        # Mock get_repo_path to return our test repo
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Test various valid paths
        valid_paths = [
            "README.md",
            "src/main.py",
            "src/utils.py",
            "./README.md",
            "src/../README.md",  # Resolves to README.md
        ]

        for path in valid_paths:
            result = validate_repo_path("test-repo", path)
            assert result.is_relative_to(sample_repo)

    def test_path_traversal_attacks(self, sample_repo: Path, temp_repos_dir: Path, monkeypatch):
        """Path traversal attacks should be blocked."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Create a secret file outside the repo
        secret_file = temp_repos_dir / "secret.txt"
        secret_file.write_text("TOP SECRET DATA")

        # These should all be blocked
        attack_paths = [
            "../secret.txt",
            "../../secret.txt",
            "../../../etc/passwd",
            "src/../../secret.txt",
            "/etc/passwd",
            "src/../../../secret.txt",
        ]

        for path in attack_paths:
            with pytest.raises(PathTraversalError):
                validate_repo_path("test-repo", path)

    def test_symlink_escape_blocked(self, malicious_repo: Path, temp_repos_dir: Path, monkeypatch):
        """Symlinks pointing outside repository should be blocked."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Try to access the symlink that escapes the repo
        with pytest.raises(PathTraversalError, match="Symlink escape detected"):
            validate_repo_path("malicious-repo", "escape_link")

    def test_absolute_path_blocked(self, sample_repo: Path, temp_repos_dir: Path, monkeypatch):
        """Absolute paths should be blocked."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Try absolute path
        with pytest.raises(PathTraversalError):
            validate_repo_path("test-repo", "/etc/passwd")


class TestSafeFilename:
    """Test filename safety checks."""

    def test_safe_filenames(self):
        """Safe filenames should return True."""
        safe_names = [
            "README.md",
            "main.py",
            "package.json",
            "file-name-123.txt",
            "my_file.rs",
        ]
        for name in safe_names:
            assert is_safe_filename(name) is True

    def test_unsafe_filenames(self):
        """Unsafe filenames should return False."""
        unsafe_names = [
            "../escape.txt",
            "../../passwd",
            "..",
            "dir/file.txt",  # Path separator
            "dir\\file.txt",  # Windows path separator
            ".env",  # Sensitive
            ".git",  # Sensitive
            ".ssh",  # Sensitive
            ".config",  # Sensitive
            ".gitignore",  # Starts with .git
            ".envrc",  # Starts with .env
        ]
        for name in unsafe_names:
            assert is_safe_filename(name) is False


class TestCVE202548384Protection:
    """Test protection against CVE-2025-48384 (hypothetical Git symlink vulnerability)."""

    def test_symlink_in_git_repo_blocked(self, temp_repos_dir: Path, monkeypatch):
        """Ensure symlinks in git repos pointing outside are blocked."""
        # Create a repo with a symlink (like CVE-2025-48384 scenario)
        repo_path = temp_repos_dir / "cve-test-repo"
        repo_path.mkdir()

        # Create target outside repo
        secret = temp_repos_dir / "secret-credentials.json"
        secret.write_text('{"api_key": "super_secret_123"}')

        # Create symlink inside repo pointing to secret
        (repo_path / "credentials.json").symlink_to(secret)

        # Mock config
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Try to read the symlinked file
        with pytest.raises(PathTraversalError, match="Symlink escape detected"):
            validate_repo_path("cve-test-repo", "credentials.json")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
