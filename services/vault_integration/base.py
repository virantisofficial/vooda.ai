# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Abstract base class for vault/secret manager integrations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class VaultSecret:
    """A secret stored in a vault."""
    path: str
    name: str
    version: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)


class VaultProviderBase(ABC):
    """Base class for vault/secret manager integrations."""

    provider: str = "unknown"

    @abstractmethod
    async def test_connection(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def list_secrets(self, prefix: str = "") -> list[VaultSecret]:
        raise NotImplementedError

    @abstractmethod
    async def get_secret_metadata(self, path: str) -> Optional[dict]:
        raise NotImplementedError

    async def rotate_secret(self, path: str, new_value: str) -> bool:
        """Write a new value to the secret path. Returns True if successful."""
        return False

    async def get_secret_version_count(self, path: str) -> int:
        """Get the number of versions for a secret."""
        return 0
