# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedFinding:
    """A single finding extracted by a parser, pre-normalization."""
    title: str
    description: str = ""
    severity: str = "medium"
    category: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None
    rule_id: Optional[str] = None
    external_id: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    code_snippet: Optional[str] = None
    source_info: dict = field(default_factory=dict)
    sink_info: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)
    confidence: float = 0.5
    raw_data: dict = field(default_factory=dict)


@dataclass
class ParseResult:
    """Result from a parser invocation."""
    findings: list[ParsedFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanner_name: str = ""
    scanner_version: str = ""
    metadata: dict = field(default_factory=dict)


class BaseParser(ABC):
    """Abstract base for all scanner finding parsers."""

    parser_name: str = "base"

    @abstractmethod
    def parse(self, content: bytes) -> ParseResult:
        """Parse raw content into structured findings."""
        ...

    def validate_structure(self, content: bytes) -> bool:
        """Optional pre-validation step."""
        return True
