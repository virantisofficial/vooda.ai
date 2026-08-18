# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Per-language comment extractor.

Used by ``SecretScanner.scan_file`` to pull comments out of source
files so they can be re-scanned with the relaxed COLLAB rules. The
motivation: developers leave the same free-form prose in code
comments that they leave in Slack — `# the prod db password is
hunter2` — and the strict CODE rules miss them because they don't
look like assignments.

Approach
--------
Regex-based extraction by file extension. We don't tokenize properly
(would require a parser per language) — that's overkill for the use
case. False positives in comment EXTRACTION (e.g. `#` inside a
string literal mistaken for a comment) are low-cost because the
COLLAB rules then re-filter via value-shape constraints. False
negatives (missed comments) are the main risk; the regex covers the
common forms.

Returns a list of `(line_num, comment_text)` tuples, with line_num
being the 1-based line in the *original* source where the comment
starts. The engine re-uses the line number when reporting the
finding so the user sees the right line in the source file.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple


# Languages where `#` to end-of-line is the comment syntax
_HASH_COMMENT_EXTS = {
    ".py", ".pyw", ".pyx",            # Python family
    ".rb", ".rake", ".gemspec",       # Ruby
    ".pl", ".pm",                     # Perl
    ".sh", ".bash", ".zsh", ".fish",  # shells
    ".ps1",                           # PowerShell (also `<# #>` blocks; covered separately)
    ".r", ".R",                       # R
    ".jl",                            # Julia
    ".yaml", ".yml",                  # YAML
    ".toml",                          # TOML
    ".conf", ".ini", ".cfg",          # Common config formats
    ".dockerfile", ".containerfile",  # Container files
    ".tf", ".tfvars", ".hcl",         # Terraform / HCL (also `//` and `/* */`)
    ".gitignore", ".dockerignore",    # Ignore files
    ".env",                           # .env files (and .env.* via filename check)
    ".mk",                            # Makefiles
}

# Languages where `//` line comments and `/* */` block comments are used
_C_FAMILY_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx",
    ".java", ".scala", ".kt", ".kts", ".groovy",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".go",
    ".rs",
    ".swift",
    ".cs", ".csx",
    ".php",
    ".dart",
    ".m", ".mm",                       # Objective-C
    ".tf", ".tfvars", ".hcl",          # HCL allows both `#` and `//`
}

# SQL — `--` to EOL plus `/* */` blocks
_SQL_EXTS = {".sql", ".pgsql", ".plsql", ".tsql"}

# HTML / XML / Vue — `<!-- -->`
_XML_EXTS = {".html", ".htm", ".xml", ".vue", ".svg", ".xsd", ".xsl"}

# Lua — `--` and `--[[ ]]`
_LUA_EXTS = {".lua"}

# Erlang / Elixir / Haskell-ish — `%` (Erlang), `#` (Elixir uses `#`)
_PERCENT_COMMENT_EXTS = {".erl", ".hrl"}


# Pre-compiled regex helpers
_LINE_HASH = re.compile(r"#\s?(.*)$")
_LINE_DSLASH = re.compile(r"//\s?(.*)$")
_LINE_DDASH = re.compile(r"--\s?(.*)$")
_LINE_PERCENT = re.compile(r"%\s?(.*)$")
_BLOCK_C = re.compile(r"/\*(.*?)\*/", re.DOTALL)
_BLOCK_HTML = re.compile(r"<!--(.*?)-->", re.DOTALL)
_BLOCK_LUA = re.compile(r"--\[\[(.*?)\]\]", re.DOTALL)
_BLOCK_PS1 = re.compile(r"<#(.*?)#>", re.DOTALL)


def _extract_line_comments(content: str, regex: re.Pattern) -> List[Tuple[int, str]]:
    """Extract single-line comments matching `regex` from each line.

    Returns 1-based (line_num, body) tuples for non-empty bodies only.
    """
    out: List[Tuple[int, str]] = []
    for i, line in enumerate(content.split("\n"), 1):
        m = regex.search(line)
        if not m:
            continue
        body = m.group(1).strip()
        if body:
            out.append((i, body))
    return out


def _extract_block_comments(content: str, regex: re.Pattern) -> List[Tuple[int, str]]:
    """Extract block comments. Returns line of opener + concatenated body."""
    out: List[Tuple[int, str]] = []
    for m in regex.finditer(content):
        line_num = content[: m.start()].count("\n") + 1
        body = m.group(1).strip()
        if body:
            # Collapse internal newlines to spaces so multi-line block
            # comments scan as one unit (avoids splitting a
            # `password=hunter2` write across two virtual lines).
            out.append((line_num, " ".join(body.split())))
    return out


def extract_comments(content: str, file_path: str) -> List[Tuple[int, str]]:
    """Return `(line_num, comment_text)` tuples for every comment in
    `content`, using the language inferred from `file_path`'s
    extension.

    Returns ``[]`` for unknown / unsupported extensions — the engine
    then skips the comment-scan pass entirely for that file.

    The line_num is 1-based and points to the START of the comment in
    the original source. Multi-line block comments report the opener
    line; the engine uses that line number for the finding.
    """
    if not content:
        return []

    ext = os.path.splitext(file_path)[1].lower()
    base = os.path.basename(file_path).lower()
    out: List[Tuple[int, str]] = []

    # `.env` and `.env.*` files use `#` comments (covered by ext check
    # for `.env` exactly; the `.env.local` case needs basename match).
    if base.startswith(".env"):
        return _extract_line_comments(content, _LINE_HASH)

    # Hash-style line comments
    if ext in _HASH_COMMENT_EXTS:
        out.extend(_extract_line_comments(content, _LINE_HASH))
        # HCL / Terraform also support `//` and `/* */`
        if ext in (".tf", ".tfvars", ".hcl"):
            out.extend(_extract_line_comments(content, _LINE_DSLASH))
            out.extend(_extract_block_comments(content, _BLOCK_C))
        # PowerShell also has `<# #>` blocks
        if ext == ".ps1":
            out.extend(_extract_block_comments(content, _BLOCK_PS1))
        return out

    # C-family
    if ext in _C_FAMILY_EXTS:
        out.extend(_extract_line_comments(content, _LINE_DSLASH))
        out.extend(_extract_block_comments(content, _BLOCK_C))
        return out

    # SQL
    if ext in _SQL_EXTS:
        out.extend(_extract_line_comments(content, _LINE_DDASH))
        out.extend(_extract_block_comments(content, _BLOCK_C))
        return out

    # HTML / XML
    if ext in _XML_EXTS:
        out.extend(_extract_block_comments(content, _BLOCK_HTML))
        return out

    # Lua
    if ext in _LUA_EXTS:
        out.extend(_extract_line_comments(content, _LINE_DDASH))
        out.extend(_extract_block_comments(content, _BLOCK_LUA))
        return out

    # Erlang / similar
    if ext in _PERCENT_COMMENT_EXTS:
        out.extend(_extract_line_comments(content, _LINE_PERCENT))
        return out

    return []


def build_virtual_comment_content(
    comments: List[Tuple[int, str]],
    total_lines_hint: int = 0,
) -> str:
    """Pad comments back into a content string at their original line
    numbers so a recursive scan reports findings at the source-file
    line, not a synthetic offset.

    `total_lines_hint` lets the caller pre-size the buffer to match
    the original file length; if 0 we use the highest comment line.
    """
    if not comments:
        return ""
    max_line = max(c[0] for c in comments)
    size = max(max_line, total_lines_hint)
    lines = [""] * size
    for line_num, text in comments:
        if 1 <= line_num <= size:
            lines[line_num - 1] = text
    return "\n".join(lines)
