# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Abstract Git provider interface for repository operations.

Supports creating branches, committing files, and opening PRs
across GitHub, GitLab, and Bitbucket.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PRResult:
    """Result from creating a pull request."""
    success: bool
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    branch_name: Optional[str] = None
    error: Optional[str] = None


@dataclass
class FileChange:
    """A single file change to commit."""
    file_path: str
    content: str          # new file content (full replacement)
    message: str = ""     # per-file commit message hint


@dataclass
class PRRequest:
    """Request to create a pull request with fixes."""
    title: str
    description: str
    source_branch: str
    target_branch: str
    files: list[FileChange] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    reviewers: list[str] = field(default_factory=list)
    draft: bool = False


class GitProvider(ABC):
    """Abstract interface for git hosting provider operations."""

    @abstractmethod
    async def create_branch(self, branch_name: str, from_branch: str) -> bool:
        """Create a new branch from an existing branch."""
        ...

    @abstractmethod
    async def commit_files(
        self,
        branch: str,
        files: list[FileChange],
        commit_message: str,
    ) -> bool:
        """Commit one or more file changes to a branch."""
        ...

    @abstractmethod
    async def create_pull_request(self, request: PRRequest) -> PRResult:
        """Create a pull request."""
        ...

    @abstractmethod
    async def get_file_content(self, file_path: str, branch: str) -> Optional[str]:
        """Get the content of a file from the repository."""
        ...

    @abstractmethod
    async def branch_exists(self, branch_name: str) -> bool:
        """Check if a branch exists."""
        ...

    async def post_pr_comment(self, pr_number: int, body: str) -> bool:
        """Post a comment on a pull request. Returns True if successful."""
        return False  # Default no-op — override in provider implementations
