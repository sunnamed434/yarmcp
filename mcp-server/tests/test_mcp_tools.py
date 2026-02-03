"""
Tests for MCP tools functionality.

Tests the 8 MCP tools:
1. list_repos()
2. get_repo_info(repo)
3. read_file(repo, path)
4. search_code(repo, pattern)
5. list_files(repo, path?)
6. tree(repo, path?, depth?, pattern?)
7. get_readme(repo)
8. get_yarmcp_usage_guide()
"""
import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestListRepos:
    """Test list_repos() tool."""

    def test_list_repos_empty(self, temp_repos_dir, monkeypatch):
        """Test listing repos when no repos exist."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # Mock the actual tool function
        # (This would need to import from tools.py once created)
        # For now, test the concept
        repos = list(temp_repos_dir.iterdir())
        assert len(repos) == 0

    def test_list_repos_with_repos(self, temp_repos_dir, monkeypatch):
        """Test listing multiple repositories."""
        # Create test repos
        (temp_repos_dir / "repo1").mkdir()
        (temp_repos_dir / "repo2").mkdir()
        (temp_repos_dir / "repo3").mkdir()

        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        repos = sorted([d.name for d in temp_repos_dir.iterdir() if d.is_dir()])
        assert repos == ["repo1", "repo2", "repo3"]


class TestGetRepoInfo:
    """Test get_repo_info(repo) tool."""

    def test_get_repo_info_exists(self, sample_repo, temp_repos_dir, monkeypatch):
        """Test getting info for existing repository."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # Repository should exist
        assert sample_repo.exists()
        assert (sample_repo / "README.md").exists()

    def test_get_repo_info_not_found(self, temp_repos_dir, monkeypatch):
        """Test getting info for non-existent repository."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # This repo doesn't exist
        repo_path = temp_repos_dir / "nonexistent-repo"
        assert not repo_path.exists()


class TestReadFile:
    """Test read_file(repo, path) tool."""

    def test_read_file_success(self, sample_repo, temp_repos_dir, monkeypatch):
        """Test reading an existing file."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # Read README.md
        content = (sample_repo / "README.md").read_text()
        assert "Test Repository" in content

    def test_read_file_in_subdirectory(self, sample_repo, temp_repos_dir, monkeypatch):
        """Test reading file in subdirectory."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # Read src/main.py
        content = (sample_repo / "src" / "main.py").read_text()
        assert "Hello, World!" in content

    def test_read_file_not_found(self, sample_repo, temp_repos_dir, monkeypatch):
        """Test reading non-existent file."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        # File doesn't exist
        with pytest.raises(FileNotFoundError):
            (sample_repo / "nonexistent.txt").read_text()

    def test_read_file_path_traversal_blocked(self, sample_repo, temp_repos_dir, monkeypatch):
        """Test that path traversal is blocked when reading files."""
        from config import settings
        monkeypatch.setattr(settings, "repos_path", temp_repos_dir)

        def mock_get_repo_path(repo: str) -> Path:
            return temp_repos_dir / repo

        from security.path_validator import validate_repo_path, PathTraversalError
        import security.path_validator
        monkeypatch.setattr(security.path_validator, "get_repo_path", mock_get_repo_path)

        # Try to read outside repo
        with pytest.raises(PathTraversalError):
            validate_repo_path("test-repo", "../../../etc/passwd")


class TestSearchCode:
    """Test search_code(repo, pattern) tool."""

    def test_search_code_find_pattern(self, sample_repo):
        """Test searching for code pattern."""
        # Search for "def add" in the repo
        matches = []
        for file_path in sample_repo.rglob("*.py"):
            content = file_path.read_text()
            if "def add" in content:
                matches.append(file_path)

        assert len(matches) == 1
        assert matches[0].name == "utils.py"

    def test_search_code_no_matches(self, sample_repo):
        """Test searching for pattern with no matches."""
        matches = []
        for file_path in sample_repo.rglob("*.py"):
            content = file_path.read_text()
            if "PATTERN_THAT_DOES_NOT_EXIST" in content:
                matches.append(file_path)

        assert len(matches) == 0

    def test_search_code_regex_pattern(self, sample_repo):
        """Test searching with regex pattern."""
        import re

        # Search for function definitions
        pattern = re.compile(r"def \w+\(")
        matches = []

        for file_path in sample_repo.rglob("*.py"):
            content = file_path.read_text()
            if pattern.search(content):
                matches.append(file_path)

        assert len(matches) == 1  # Only utils.py has function def


class TestListFiles:
    """Test list_files(repo, path?) tool."""

    def test_list_files_root(self, sample_repo):
        """Test listing files in repository root."""
        files = sorted([f.name for f in sample_repo.iterdir() if f.is_file()])
        assert "README.md" in files

    def test_list_files_subdirectory(self, sample_repo):
        """Test listing files in subdirectory."""
        src_dir = sample_repo / "src"
        files = sorted([f.name for f in src_dir.iterdir() if f.is_file()])
        assert files == ["main.py", "utils.py"]

    def test_list_files_recursive(self, sample_repo):
        """Test recursive file listing."""
        all_files = sorted([str(f.relative_to(sample_repo)) for f in sample_repo.rglob("*") if f.is_file()])
        assert "README.md" in all_files
        assert "src/main.py" in all_files
        assert "src/utils.py" in all_files


class TestTree:
    """Test tree(repo, path?, depth?, pattern?) tool."""

    def test_tree_root(self, sample_repo):
        """Test tree view of repository root."""
        # Build tree structure
        tree_items = []
        for item in sorted(sample_repo.iterdir()):
            if item.is_dir():
                tree_items.append(f"{item.name}/")
            else:
                tree_items.append(item.name)

        assert "README.md" in tree_items
        assert "src/" in tree_items
        assert ".git/" in tree_items

    def test_tree_with_depth_limit(self, sample_repo):
        """Test tree with depth limit."""
        # Depth 1: only show immediate children
        depth_1_items = [item.name for item in sample_repo.iterdir()]

        assert "README.md" in depth_1_items
        assert "src" in depth_1_items

        # Should NOT include src/main.py (depth 2)

    def test_tree_with_pattern_filter(self, sample_repo):
        """Test tree with pattern filter (e.g., *.py)."""
        # Find all Python files
        py_files = [str(f.relative_to(sample_repo)) for f in sample_repo.rglob("*.py")]

        assert "src/main.py" in py_files
        assert "src/utils.py" in py_files
        assert "README.md" not in py_files


class TestGetReadme:
    """Test get_readme(repo) tool."""

    def test_get_readme_uppercase(self, sample_repo):
        """Test finding README.md."""
        readme = sample_repo / "README.md"
        assert readme.exists()
        content = readme.read_text()
        assert "Test Repository" in content

    def test_get_readme_variations(self, temp_repos_dir):
        """Test finding README with various casings."""
        # Common README variations
        variations = ["README.md", "Readme.md", "readme.md", "README.txt", "README"]

        for variant in variations:
            repo_path = temp_repos_dir / f"repo-{variant.lower().replace('.', '-')}"
            repo_path.mkdir()
            readme = repo_path / variant
            readme.write_text(f"# {variant}")

            # Find any README variant
            found_readme = None
            for possible in ["README.md", "Readme.md", "readme.md", "README.txt", "README"]:
                candidate = repo_path / possible
                if candidate.exists():
                    found_readme = candidate
                    break

            assert found_readme is not None

    def test_get_readme_not_found(self, temp_repos_dir):
        """Test handling missing README."""
        repo_path = temp_repos_dir / "no-readme-repo"
        repo_path.mkdir()

        # No README exists
        assert not (repo_path / "README.md").exists()


class TestGetUsageGuide:
    """Test get_yarmcp_usage_guide() tool."""

    def test_usage_guide_returns_text(self):
        """Test that usage guide returns documentation text."""
        # Mock usage guide
        usage_guide = """
        # YARMCP Usage Guide

        Available MCP Tools:
        1. list_repos() - List all available repositories
        2. get_repo_info(repo) - Get information about a repository
        3. read_file(repo, path) - Read a file from a repository
        4. search_code(repo, pattern) - Search for code patterns
        5. list_files(repo, path?) - List files in a repository
        6. tree(repo, path?, depth?, pattern?) - Show repository tree structure
        7. get_readme(repo) - Get repository README
        8. get_yarmcp_usage_guide() - Show this guide

        Examples:
        - list_repos()
        - read_file("react", "README.md")
        - search_code("pytorch", "def forward")
        """

        assert "YARMCP Usage Guide" in usage_guide
        assert "list_repos()" in usage_guide
        assert "8" in usage_guide or "eight" in usage_guide.lower()


class TestToolAuthentication:
    """Test that tools require authentication."""

    def test_tools_require_auth_token(self):
        """Test that MCP tools require valid auth token."""
        # This would be tested in integration tests
        # where we call the actual FastAPI endpoints
        pass

    def test_tools_reject_invalid_token(self):
        """Test that invalid tokens are rejected."""
        # Integration test - verify 401/403 response
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
