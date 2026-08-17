# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Base classes for secret detection rules."""

import fnmatch
from dataclasses import dataclass, field


@dataclass
class SecretRule:
    rule_id: str
    title: str
    secret_type: str
    severity: str
    pattern: str
    keywords: list[str] = field(default_factory=list)
    confidence: float = 0.9
    description: str = ""
    fix_hint: str = ""
    cwe: str = "CWE-798"
    multiline: bool = False
    # Per-context confidence override. The default `confidence` is
    # tuned against source-code corpora — short hardcoded passwords
    # in code are usually test scaffolding so we run those rules
    # cool. The same regex against a Jira description or Slack
    # message is a different signal entirely (typically a real
    # disclosure), so we want to score it hotter.
    #
    # Keys are the `content_type` values yielded by source scanner
    # adapters (see services/source_scanners/base.py): currently
    # "message", "page", "comment", "file", "env_var", "log_line".
    # Missing keys fall through to the default `confidence`.
    #
    # Example — bump GEN-003 (Hardcoded Password) to 0.65 in chat
    # / wiki / ticket content while keeping it at 0.30 in source:
    #     confidence_by_context={"message": 0.65, "page": 0.65,
    #                             "comment": 0.65}
    #
    # Surfaced after the TRUF-5 detection miss + WEAK workaround
    # (Q2 2026). The ideal long-term path is to deprecate the WEAK
    # detector once enough rules are calibrated this way.
    confidence_by_context: dict[str, float] = field(default_factory=dict)

    # ── Surface targeting (added 2026-05-03) ────────────────────────
    # Different content types (source code vs Slack message vs Jira
    # description) need different regex shapes, not just different
    # confidences. `password = "x"` in a .py file is structured;
    # `password=hdgshui@sn12` in a Slack message is free-form text.
    # One regex can't be tuned for both without unacceptable FPs in
    # at least one direction.
    #
    # Two complementary mechanisms below let a rule restrict itself
    # to the surfaces it was calibrated against:
    #
    # surface_targeting — when set, rule fires ONLY on these
    #   content_type values. Use for collab-only or code-only
    #   variants of generic patterns.
    #
    # surface_excluded — when set, rule fires everywhere EXCEPT
    #   these values. Use to retire a rule from a surface where a
    #   purpose-built variant has taken over (e.g. quoted-only
    #   GEN-003 stops firing on collab content once GEN-003-COLLAB
    #   ships).
    #
    # Both default to None (= "no restriction") so the ~860 rules
    # in the library that don't care about surface stay unchanged.
    # A None content_type (the git-scan path) bypasses targeting
    # entirely — code-side rules that don't care about content_type
    # just keep working.
    surface_targeting: list[str] | None = None
    surface_excluded: list[str] | None = None

    def confidence_for(self, content_type: str | None) -> float:
        """Resolve effective confidence for a given content_type.

        Returns the per-context override if one exists, else the
        default `confidence`. Pure function — no side effects;
        cheap enough to call per match.
        """
        if content_type and self.confidence_by_context:
            return self.confidence_by_context.get(content_type, self.confidence)
        return self.confidence

    def applies_to_surface(self, content_type: str | None) -> bool:
        """Should this rule run on content with the given content_type?

        Decision matrix:
          - content_type is None (git-scan path): always run, unless
            the rule explicitly said it only runs on a list of
            content types (surface_targeting set). This keeps the
            git path's behaviour stable for the ~860 rules that
            don't set either field.
          - surface_targeting set + content_type matches: run
          - surface_targeting set + content_type doesn't match: skip
          - surface_excluded set + content_type matches: skip
          - neither set: run
        """
        if self.surface_targeting is not None:
            return content_type is not None and content_type in self.surface_targeting
        if content_type is not None and self.surface_excluded:
            return content_type not in self.surface_excluded
        return True
    # When True, the engine compiles the pattern WITHOUT re.IGNORECASE, so
    # character classes like [A-Z0-9] match only uppercase. Required for
    # strict-format partner tokens whose spec is case-specific (AWS AKIA,
    # Etherscan 34-char uppercase, Tencent AKID, etc.). Default False for
    # backwards compatibility with older rules that rely on IGNORECASE.
    case_sensitive: bool = False

    # Override for the verifier provider key. By default the engine
    # derives the provider from `secret_type.split("_")[0]` — fine for
    # single-word providers (`aws_secret`, `github_token`). Multi-word
    # providers (`azure_devops_pat`) would otherwise route to the
    # wrong verifier (`azure` instead of `azure_devops`). Setting this
    # field forces the engine to use the explicit value instead. Added
    # 2026-05-03 to wire the new enterprise-source verifiers without
    # breaking the single-word convention 880 other rules rely on.
    provider_override: str | None = None
    # fnmatch-style globs of file paths where this rule should NOT fire, even
    # when the keyword pre-filter and regex would match. Used to suppress
    # known-structural false positives at the source rather than relying on
    # AI triage to filter them (cheaper, more reliable, and can't regress
    # from a prompt edit). Paths are matched relative to the repo root when
    # a root is known; otherwise against the absolute path. Patterns use
    # `*` / `**` wildcards — e.g. "**/api/docs/*.yaml" matches Docker-style
    # OpenAPI specs that contain schema-example tokens resembling secrets.
    # Gold-label-validated 2026-04-24: the measured false-alarm rate on
    # moby `api/docs/v*.yaml` was 105/112 — nearly pure noise.
    exclude_path_patterns: list[str] = field(default_factory=list)

    # ── 2-pass post-filter (added 2026-05-24) ──────────────────────
    # The re2 fast path cannot compile lookahead/lookbehind patterns
    # like ``\b(TOKEN_PATTERN)\b(?=[\s\S]{0,120}provider_keyword)``.
    # Instead of keeping such rules on the regex+timeout fallback
    # forever (with ReDoS exposure + missed detections on timeout),
    # we split the original semantics into two passes:
    #
    #   Pass 1 — `pattern` finds the candidate token (re2-compatible)
    #   Pass 2 — Python validates keyword proximity post-match here
    #
    # Fields:
    #   post_filter_keywords    list of strings; match passes Pass 2
    #                           iff at least one keyword is found in
    #                           the proximity window (when
    #                           ``post_filter_required=True``) or
    #                           NONE is found (when False — equivalent
    #                           to a negative lookahead).
    #   post_filter_window      half-window in characters around the
    #                           match.  e.g. 200 = scan 200 chars
    #                           before AND/OR after the match.
    #   post_filter_direction   "after" (default — most lookaheads
    #                           are forward), "before" (lookbehinds),
    #                           or "both".
    #   post_filter_required    True for positive lookahead
    #                           (``(?=…)``), False for negative
    #                           lookahead (``(?!…)``).
    #
    # Defaults are no-op (empty keyword list) — the ~879 rules that
    # don't need a post-filter continue to behave exactly as before.
    post_filter_keywords: list[str] = field(default_factory=list)
    post_filter_window: int = 200
    post_filter_direction: str = "after"
    post_filter_required: bool = True

    # ── AND-of-groups proximity (for multi-stage lookaheads) ───────
    # post_filter_groups expresses the `(?=.*KW1.*KW2)` semantics —
    # ALL of the inner groups must be present in the proximity window,
    # where each group is itself an "any of these keywords" set.
    # Example for Rollbar:
    #   post_filter_groups = [
    #     ["rollbar"],                        # must have "rollbar"
    #     ["server", "post_server_item"],     # AND any of {server, post_server_item}
    #   ]
    # Combines with post_filter_keywords if both are set (both must
    # be satisfied).  Most rules use one or the other, not both.
    post_filter_groups: list[list[str]] = field(default_factory=list)

    def passes_post_filter(self, content: str, match_start: int, match_end: int) -> bool:
        """Apply the 2-pass proximity checks.

        Returns True when the rule has neither post_filter_keywords
        nor post_filter_groups (most rules — no-op fast path).

        When ``post_filter_keywords`` is set, the rule passes iff
        ANY of those keywords appears in the proximity window
        (positive-lookahead semantics) — or NONE of them appear when
        ``post_filter_required=False`` (negative-lookahead semantics).

        When ``post_filter_groups`` is set, the rule passes iff EVERY
        group has at least one of its keywords in the window — the
        AND-of-(OR-within-group) semantics that the original
        ``(?=.*KW1.*KW2)`` lookaheads expressed.

        When both are set, BOTH conditions must hold.

        Case-insensitive throughout — matches the original lookahead
        semantics which all used (?i) flags.
        """
        if not self.post_filter_keywords and not self.post_filter_groups:
            return True

        # Compute the proximity slice once; same for both checks.
        window = max(0, self.post_filter_window)
        if self.post_filter_direction == "after":
            slice_start = match_end
            slice_end = match_end + window
        elif self.post_filter_direction == "before":
            slice_start = max(0, match_start - window)
            slice_end = match_start
        else:  # "both"
            slice_start = max(0, match_start - window)
            slice_end = match_end + window
        nearby = content[slice_start:slice_end].lower()

        # Check 1: post_filter_keywords (any-of semantics)
        if self.post_filter_keywords:
            keyword_found = any(kw.lower() in nearby for kw in self.post_filter_keywords)
            if self.post_filter_required:
                if not keyword_found:
                    return False
            else:
                # Negative — pass only if NO keyword nearby
                if keyword_found:
                    return False

        # Check 2: post_filter_groups (AND-of-OR-within-group semantics)
        if self.post_filter_groups:
            for group in self.post_filter_groups:
                if not any(kw.lower() in nearby for kw in group):
                    return False

        return True

    def excluded_for_path(self, rel_path: str) -> bool:
        """Return True if this rule should skip the given file path.

        Checks the path against every pattern in `exclude_path_patterns`
        using fnmatch (so glob-style `*` and `**` wildcards work). The
        engine calls this during the scan_file keyword pre-filter so an
        excluded rule never reaches the regex phase.
        """
        if not self.exclude_path_patterns or not rel_path:
            return False
        for pattern in self.exclude_path_patterns:
            if fnmatch.fnmatch(rel_path, pattern):
                return True
        return False
