# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""Codemod: rewrite lookahead patterns in detector files as 2-pass post_filter_*.

Reads each detector .py file, finds SecretRule(...) constructors whose pattern
contains a lookahead, parses the lookahead structure, and rewrites:

    pattern=r'BASE(?=.*KW1|.*KW2)'

into:

    pattern=r'BASE'
    post_filter_keywords=["KW1", "KW2"]
    post_filter_window=500

Operates safely:
  - skips rules where the lookahead shape isn't a recognised template
    (multi-stage `(?=.*KW1.*KW2)`, lookbehind, negative-lookahead) —
    those keep their original pattern + stay on the regex fallback
  - dry-run mode emits the proposed edits without writing to disk
  - re-runnable: a rule that already has post_filter_keywords set
    is skipped (idempotent)
  - preserves all other rule fields exactly

Track-A Option B-1 (2026-05-24).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Optional

# Recognise the most common single-stage lookahead shapes used in
# the Vooda rule pack.  Returns (keywords, window) or None.
#
# Patterns handled:
#   (?=.*KW)
#   (?=.*KW1|.*KW2|.*KW3)
#   (?=.*(KW1|KW2|KW3))
#   (?=.*(?:KW1|KW2|KW3))
#   (?=[\s\S]{0,N}KW)
#   (?=[\s\S]{0,N}(?:KW1|KW2))
#   (?=[\s\S]{0,N}(KW1|KW2))
#
# NOT handled (skipped, left on regex fallback):
#   (?=.*KW1.*KW2)            — multi-stage AND
#   (?<=...)                  — lookbehind
#   (?!...)                   — negative lookahead
#   nested lookarounds inside the lookahead
LOOKAHEAD_TAIL_RE = re.compile(
    r"""
    \(\?=                                     # opening (?=
    (?:
        # bounded window: [\s\S]{0,N}...
        \[\\s\\S\]\{0,(?P<window_bounded>\d+)\}
      |
        # unbounded: .* (greedy or lazy)
        \.\*\??
    )
    (?P<body>
        (?:                                   # body is either:
            \([\?:]*                          #   a group: (...)
            (?P<group_body>[^()]+)
            \)
          |
            (?P<single_kw>[A-Za-z0-9._-]+)    #   or a single bare keyword
        )
    )
    \)$
    """,
    re.VERBOSE,
)

# Also try the alternation-of-.* shape: (?=.*KW1|.*KW2|.*KW3)
LOOKAHEAD_ALT_RE = re.compile(
    r"""
    \(\?=
    \.\*(?P<first>[A-Za-z0-9._-]+)
    (?P<rest>(?:\|\.\*[A-Za-z0-9._-]+)+)
    \)$
    """,
    re.VERBOSE,
)


def _unescape_for_substring(s: str) -> str:
    """Strip regex metacharacter escapes for use as a substring needle.

    Keywords extracted from lookahead alternations carry their regex
    escapes (e.g. `loops\\.so`).  post_filter_keywords is checked via
    substring matching (case-insensitive), so the backslash makes the
    literal `loops\\.so` substring NOT match `loops.so` in source.
    Unescape the common metacharacters before emitting.
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in ".-_/: ":
            out.append(s[i + 1])
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


@dataclass
class LookaheadRewrite:
    base_pattern: str            # pattern with lookahead stripped
    keywords: list[str]          # any-of (or post_filter_keywords)
    window: int
    direction: str = "after"     # "after" | "before" | "both"
    groups: list[list[str]] | None = None  # AND-of-(OR-within-group)


# Shape 1: before-or-after alternation.  Two equivalent halves
# joined by `|` — TOKEN followed-by KEYWORD, OR KEYWORD followed-by
# TOKEN.  Common pattern in trufflehog_port_* for "keyword anywhere
# in either direction" semantics.  The token regex appears identical
# in both branches (which is how we identify it).
#
# Examples:
#   \b(sk-[A-Za-z0-9]{48})\b(?=[\s\S]{0,120}(?:stability|STABILITY))|(?:stability|STABILITY)[\s\S]{0,120}\b(sk-[A-Za-z0-9]{48})\b
#   \b([a-f0-9]{32})\b(?=[\s\S]{0,120}rollbar)|rollbar[\s\S]{0,120}\b([a-f0-9]{32})\b
# Matches either `(?:KW1|KW2)` non-cap group, `(KW1|KW2)` cap group,
# or a bare keyword like `scaleway`.  The inner non-capturing
# variants get reduced to the same keyword list downstream.
_KW_GROUP = r"""(?:\((?:\?:)?(?P<{tag}>[^)]+)\)|(?P<{tag}_bare>[A-Za-z0-9._-]+))"""

BEFORE_OR_AFTER_RE = re.compile(
    r"""
    ^
    (?P<tok_first>\\b\([^)]+\)\\b)                  # \b(TOKEN_REGEX)\b
    \(\?=
    \[\\s\\S\]\{0,(?P<window>\d+)\}
    """ + _KW_GROUP.format(tag="kw_after") + r"""
    \)
    \|
    """ + _KW_GROUP.format(tag="kw_before") + r"""
    \[\\s\\S\]\{0,(?P<window2>\d+)\}
    (?P<tok_second>\\b\([^)]+\)\\b)                 # \b(TOKEN_REGEX)\b
    $
    """,
    re.VERBOSE,
)


def _match_before_or_after_alternation(pattern: str) -> Optional[LookaheadRewrite]:
    """Detect and rewrite the before-or-after alternation shape."""
    m = BEFORE_OR_AFTER_RE.match(pattern)
    if not m:
        return None
    # Validate the two token regexes are identical — sanity check we
    # didn't mis-match a fundamentally different pattern shape.
    if m.group("tok_first") != m.group("tok_second"):
        return None
    base = m.group("tok_first")
    window = int(m.group("window"))
    kw_after_grouped = m.group("kw_after") or ""
    kw_after_bare = m.group("kw_after_bare") or ""
    kw_before_grouped = m.group("kw_before") or ""
    kw_before_bare = m.group("kw_before_bare") or ""
    kw1 = (kw_after_grouped or kw_after_bare).lstrip("?:")
    kw2 = (kw_before_grouped or kw_before_bare).lstrip("?:")
    keywords = [k.strip() for k in kw1.split("|") if k.strip()]
    if kw2 and kw2 != kw1:
        keywords.extend(k.strip() for k in kw2.split("|") if k.strip())
    keywords = [_unescape_for_substring(k) for k in keywords]
    seen = set()
    keywords = [k for k in keywords if not (k.lower() in seen or seen.add(k.lower()))]
    if not keywords:
        return None
    return LookaheadRewrite(
        base_pattern=base,
        keywords=keywords,
        window=window,
        direction="both",
    )


# Shape 2: multi-stage AND lookahead.
#   \b(TOK)\b(?=.*GROUP1.*GROUP2)
# where GROUP1 and GROUP2 are either single keywords or (kw|kw)
# alternations.  Each group must independently match in the window.
MULTI_STAGE_AND_RE = re.compile(
    r"""
    ^
    (?P<base>.*?)                                   # token regex (lazy)
    \(\?=
    \.\*
    """ + _KW_GROUP.format(tag="g1") + r"""
    \.\*
    """ + _KW_GROUP.format(tag="g2") + r"""
    \)
    $
    """,
    re.VERBOSE,
)


def _match_multi_stage_and(pattern: str) -> Optional[LookaheadRewrite]:
    """Detect and rewrite the multi-stage AND lookahead shape."""
    m = MULTI_STAGE_AND_RE.match(pattern)
    if not m:
        return None
    base = m.group("base")
    g1 = (m.group("g1") or m.group("g1_bare") or "").lstrip("?:")
    g2 = (m.group("g2") or m.group("g2_bare") or "").lstrip("?:")
    parsed_groups: list[list[str]] = []
    for raw in (g1, g2):
        items = [_unescape_for_substring(k.strip()) for k in raw.split("|") if k.strip()]
        seen = set()
        items = [k for k in items if not (k.lower() in seen or seen.add(k.lower()))]
        if not items:
            return None
        parsed_groups.append(items)
    return LookaheadRewrite(
        base_pattern=base,
        keywords=[],
        window=500,
        direction="after",
        groups=parsed_groups,
    )


def parse_lookahead(pattern: str) -> Optional[LookaheadRewrite]:
    """Extract base + keywords from a recognised lookahead shape.

    Returns None if pattern uses a lookahead shape we don't know how
    to rewrite (some lookbehinds, complex nested forms).  Caller
    leaves those rules untouched.

    Recognised shapes (in order of detection):

    1. **Before-or-after alternation** —
       ``\\b(TOK)\\b(?=[\\s\\S]{0,N}KW)|(?:KW)[\\s\\S]{0,N}\\b(TOK)\\b``
       Rewrites to ``\\b(TOK)\\b`` + post_filter_direction="both".

    2. **Multi-stage AND** —
       ``\\b(TOK)\\b(?=.*GROUP1.*GROUP2)``
       Rewrites to ``\\b(TOK)\\b`` + post_filter_groups=[[g1...], [g2...]].

    3. **Single-stage** (the original codemod handled this) —
       ``\\b(TOK)\\b(?=.*KW)`` or ``(?=[\\s\\S]{0,N}KW)``
       Rewrites to ``\\b(TOK)\\b`` + post_filter_keywords=[KW...].
    """
    if "(?<" in pattern or "(?!" in pattern:
        return None
    if "(?=" not in pattern:
        return None

    # Shape 1: before-or-after alternation.
    # Anchor: pattern contains "|" at top level AND BOTH sides have the same TOKEN regex.
    # Detect via this specific shape: `<TOK>(?=...)|(?:KW)[\s\S]{0,N}<TOK>`
    boa = _match_before_or_after_alternation(pattern)
    if boa is not None:
        return boa

    # Shape 2: multi-stage AND lookahead.
    msa = _match_multi_stage_and(pattern)
    if msa is not None:
        return msa

    # Try the bounded-or-unbounded-single-body form
    m = LOOKAHEAD_TAIL_RE.search(pattern)
    if m:
        base = pattern[:m.start()]
        window = int(m.group("window_bounded")) if m.group("window_bounded") else 500
        if m.group("single_kw"):
            keywords = [m.group("single_kw")]
        else:
            group_body = m.group("group_body")
            # Strip ?: prefix if present (non-capturing group marker)
            if group_body.startswith("?:"):
                group_body = group_body[2:]
            # Split on |, strip whitespace, drop empties
            keywords = [k.strip() for k in group_body.split("|") if k.strip()]
        # Unescape regex metacharacters so the substring check works
        keywords = [_unescape_for_substring(k) for k in keywords]
        # Dedupe case-insensitively (the post_filter is case-insensitive)
        seen = set()
        keywords = [k for k in keywords if not (k.lower() in seen or seen.add(k.lower()))]
        if keywords:
            return LookaheadRewrite(base_pattern=base, keywords=keywords, window=window)

    # Try the alternation-of-.* form
    m = LOOKAHEAD_ALT_RE.search(pattern)
    if m:
        base = pattern[:m.start()]
        keywords = [m.group("first")]
        rest = m.group("rest")
        for chunk in re.findall(r"\|\.\*([A-Za-z0-9._-]+)", rest):
            keywords.append(chunk)
        keywords = [_unescape_for_substring(k) for k in keywords]
        # Dedupe case-insensitively
        seen = set()
        keywords = [k for k in keywords if not (k.lower() in seen or seen.add(k.lower()))]
        if keywords:
            return LookaheadRewrite(base_pattern=base, keywords=keywords, window=500)

    return None


# Match an entire SecretRule(...) constructor in source — captures
# the constructor body so we can locate + modify the pattern field
# and inject the post_filter_* fields.
#
# Constraints:
#   - constructor must be at top-level (one indent level inside RULES = [...])
#   - the rule_id field is on its own line
#   - the pattern field uses r"..." or r'...' (raw string literal)
#
# These match the convention used throughout services/secret_scan/detectors/*.
RULE_ID_RE = re.compile(r"""rule_id\s*=\s*['"]([A-Z0-9_-]+)['"]""")
# Match `pattern=r'...'` or `pattern=r"..."`, single line only
PATTERN_RE = re.compile(r"""(\s*)pattern\s*=\s*r(['"])(.+?)\2,?\s*$""", re.MULTILINE)


def rewrite_file(path: str, *, dry_run: bool = False, only_ids: set[str] | None = None) -> dict:
    """Rewrite all single-stage lookahead rules in `path`.

    Returns a stats dict: {rewritten: [rule_ids], skipped: [(rule_id, reason)]}.
    """
    with open(path) as f:
        src = f.read()

    stats = {"rewritten": [], "skipped_unrecognised": [], "skipped_already_done": []}

    # Walk SecretRule(...) blocks by finding rule_id lines and using
    # them as anchors.  For each rule, scan a bounded window AFTER the
    # rule_id line to find the corresponding pattern= and inject before
    # confidence= (or the constructor close `)`).
    lines = src.split("\n")
    new_lines = list(lines)  # we mutate this

    # Map line_idx of each rule_id occurrence to the rule_id
    rule_id_lines = []
    for i, line in enumerate(lines):
        m = RULE_ID_RE.search(line)
        if m:
            rule_id_lines.append((i, m.group(1)))

    # Process rules in reverse order so line-index mutations don't
    # invalidate later ones.
    for i, rule_id in reversed(rule_id_lines):
        if only_ids is not None and rule_id not in only_ids:
            continue
        # Scan from rule_id line down up to 30 lines for pattern=
        block_end = min(i + 30, len(lines))
        # Locate pattern= line + post_filter_keywords= line in this block
        pat_idx = None
        already_has_post_filter = False
        for j in range(i, block_end):
            if PATTERN_RE.match(lines[j]):
                pat_idx = j
            if "post_filter_keywords" in lines[j]:
                already_has_post_filter = True
                break
            if lines[j].rstrip().endswith("),"):  # end of constructor
                break
        if pat_idx is None:
            continue
        if already_has_post_filter:
            stats["skipped_already_done"].append(rule_id)
            continue

        pat_line = lines[pat_idx]
        m = PATTERN_RE.match(pat_line)
        if not m:
            continue
        indent = m.group(1)
        quote = m.group(2)
        original_pattern = m.group(3)

        rewrite = parse_lookahead(original_pattern)
        if not rewrite:
            stats["skipped_unrecognised"].append((rule_id, original_pattern[:80]))
            continue

        # Build the replacement lines:
        # - replace pattern= line with stripped base
        # - inject post_filter_* fields appropriate to the rewrite shape
        new_pattern_line = f"{indent}pattern=r{quote}{rewrite.base_pattern}{quote},"
        post_filter_lines = [
            f"{indent}# 2-pass: lookahead → post_filter_* (Option B-1 codemod, 2026-05-24).",
        ]
        if rewrite.groups:
            # Multi-stage AND: use post_filter_groups
            groups_repr = ", ".join(
                "[" + ", ".join(repr(k) for k in grp) + "]"
                for grp in rewrite.groups
            )
            post_filter_lines.append(f"{indent}post_filter_groups=[{groups_repr}],")
            post_filter_lines.append(f"{indent}post_filter_window={rewrite.window},")
        else:
            kw_repr = ", ".join(repr(k) for k in rewrite.keywords)
            post_filter_lines.append(f"{indent}post_filter_keywords=[{kw_repr}],")
            post_filter_lines.append(f"{indent}post_filter_window={rewrite.window},")
            # Direction defaults to "after" — only emit when non-default
            if rewrite.direction != "after":
                post_filter_lines.append(f"{indent}post_filter_direction={rewrite.direction!r},")

        # Splice into new_lines
        new_lines[pat_idx] = new_pattern_line
        for offset, pf_line in enumerate(post_filter_lines, start=1):
            new_lines.insert(pat_idx + offset, pf_line)

        stats["rewritten"].append(rule_id)

    new_src = "\n".join(new_lines)
    if not dry_run and new_src != src:
        with open(path, "w") as f:
            f.write(new_src)

    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", default="services/secret_scan/detectors")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only-files", nargs="*", help="Restrict to these basenames")
    args = ap.parse_args()

    summary = {"rewritten_total": 0, "skipped_total": 0, "per_file": {}}
    files = sorted(f for f in os.listdir(args.dir) if f.endswith(".py") and f != "__init__.py")
    if args.only_files:
        files = [f for f in files if f in args.only_files]

    for f in files:
        path = os.path.join(args.dir, f)
        stats = rewrite_file(path, dry_run=args.dry_run)
        if stats["rewritten"] or stats["skipped_unrecognised"]:
            summary["per_file"][f] = stats
            summary["rewritten_total"] += len(stats["rewritten"])
            summary["skipped_total"] += len(stats["skipped_unrecognised"])

    print(f"\n{'─' * 70}")
    print(f"REWRITE SUMMARY ({'DRY-RUN' if args.dry_run else 'APPLIED'})")
    print(f"{'─' * 70}")
    print(f"Total rewritten:  {summary['rewritten_total']}")
    print(f"Total skipped:    {summary['skipped_total']}")
    print()
    for fname, stats in summary["per_file"].items():
        print(f"  {fname}:  rewritten={len(stats['rewritten'])}  skipped={len(stats['skipped_unrecognised'])}")
        if stats["skipped_unrecognised"]:
            for rid, pat in stats["skipped_unrecognised"][:3]:
                print(f"    skipped: {rid}  reason: pattern shape not auto-rewritable")
                print(f"             {pat[:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
