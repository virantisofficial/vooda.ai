# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Per-extension `content_type` routing for file-based source adapters.

Cloud storage (S3, OneDrive, SharePoint, Box, Azure Blob, Google Drive)
holds two categories of text-readable files:

  1. Structured config / source — `.env`, `.yaml`, `.json`, `.py`, `.tf`,
     `.ini`, `.toml`, etc. Code-shaped writes; CODE rules
     (strict-quoted) match these well.

  2. Free-form prose — `.md`, `.txt`, `.rst`, `.csv`, runbooks,
     READMEs, on-call notes, etc. Look like collab content; the
     COLLAB rules (relaxed-quoting, value-shape filtered) catch the
     `password is hunter2` shape that strict-quoted rules miss.

This helper picks the right `content_type` so the scan engine routes
the right rule cohort:

  - `"file"`  → CODE rules fire (default).
  - `"page"`  → COLLAB rules fire (prose).

Provider rules (AWS, GitHub, Slack tokens, etc.) are surface-agnostic
and fire regardless — both .env and .md files get full provider
coverage. This routing only changes which generic GEN-* rules fire.

Why this matters
----------------
Without this routing, `notes.txt` containing
    "the prod admin password is hunter2-realdeal"
would silently miss the strict GEN-003 rule (no quotes, no `=`-style
assignment), even though the same content in a Slack message would
fire GEN-003-COLLAB. The fix is one routing call per adapter.
"""
from __future__ import annotations

import os


# Free-form prose extensions — route to "page" so COLLAB rules fire.
# Markdown / plain-text / restructured-text / asciidoc / org-mode are
# the universe of prose formats that show up in cloud storage.
# CSV / TSV / log files are also treated as prose because they
# typically contain free-form data rows where structured parsing
# wouldn't help.
_PROSE_EXTENSIONS = {
    ".md", ".markdown", ".mdx",
    ".txt", ".text",
    ".rst", ".rest",
    ".adoc", ".asciidoc", ".asc",
    ".org",
    ".tex",
    ".csv", ".tsv",
    ".log",
}


def content_type_for_path(path: str, default: str = "file") -> str:
    """Return the right `ScanableContent.content_type` for a file path
    based on its extension.

    Free-form prose files (.md, .txt, .rst, .csv, .log, etc.) are
    routed to ``"page"`` so the COLLAB rules in
    ``services.secret_scan.detectors.generic_collab`` fire. Everything
    else stays at the caller-provided ``default`` (almost always
    ``"file"``) so the strict CODE rules handle structured content.

    Provider rules (AWS keys, GitHub PATs, Slack tokens, etc.) are
    surface-agnostic and fire regardless of the returned content_type.

    Args:
        path: The object key / file path. Only the extension is read.
        default: Returned when the extension is not in the prose
            allowlist. Caller should pass the surface they were
            already using ("file" for cloud storage, "log_line" for
            log streams, etc.) so the change is opt-in additive.

    Returns:
        Either ``"page"`` (prose) or ``default`` (everything else).
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in _PROSE_EXTENSIONS:
        return "page"
    return default
