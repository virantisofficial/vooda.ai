# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Abstract base class for non-git source scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, AsyncIterator
from datetime import datetime


@dataclass
class ScanableContent:
    """A unit of text content extracted from a non-git source."""
    source_locator: str       # e.g., "slack://C04ABC/1712345.123", "s3://bucket/key"
    content: str              # the text to scan for secrets
    content_type: str         # "message", "page", "comment", "file", "env_var", "log_line"
    timestamp: Optional[datetime] = None
    author: Optional[str] = None
    deep_link_url: Optional[str] = None   # URL to open in the source system
    metadata: dict = field(default_factory=dict)


class SourceAdapter(ABC):
    """Base class for extracting scannable content from non-git sources.

    Each adapter handles authentication, pagination, rate limiting,
    and incremental sync for one source type. Yields ScanableContent
    objects that feed into SecretScanner.scan_file().
    """

    source_type: str = "unknown"

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test if the source is reachable. Returns {"status": "success"|"error", "message": "..."}."""
        raise NotImplementedError

    @abstractmethod
    async def extract_content(self, sync_state: dict) -> AsyncIterator[ScanableContent]:
        """Yield content items from the source.

        Args:
            sync_state: Previous sync cursors (timestamps, page versions, etc.)
                        Empty dict on first scan.

        Yields:
            ScanableContent items to scan for secrets.
        """
        raise NotImplementedError

    @abstractmethod
    def get_updated_sync_state(self) -> dict:
        """Return updated sync state after extraction completes.

        Called after extract_content() finishes to persist
        cursors/watermarks for the next incremental scan.
        """
        raise NotImplementedError

    async def estimate_scope(self) -> dict:
        """Return estimated item count for progress reporting.

        Returns:
            {"estimated_items": int, "channels": int, ...} or empty dict.
        """
        return {}
