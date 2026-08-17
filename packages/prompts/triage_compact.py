# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Compact prompt template for AI triage with small local models (< 7B parameters).
Optimized for: minimal token usage, strict JSON output, no over-generation.
Used when AIModelConfig.use_compact_prompt is True.
"""

TRIAGE_SYSTEM_PROMPT_COMPACT = """You are a security scanner false positive analyzer.
Rules:
- Output ONLY valid JSON. No text before or after the JSON.
- Classify the finding as one of: likely_true_positive, likely_false_positive, needs_review.
- Be concise. Maximum 2 sentences for reasoning."""

TRIAGE_PROMPT_COMPACT = """Analyze this security finding:

Title: {title}
Severity: {severity}
File: {file_path}:{line_start}
Description: {description}

Code:
```
{code_snippet}
```

Respond with ONLY this JSON:
{{"classification": "likely_true_positive|likely_false_positive|needs_review", "confidence_score": 0.0-1.0, "reasoning_summary": "1-2 sentences", "recommended_next_action": "mark_true_positive|mark_false_positive|request_human_review"}}"""

TRIAGE_COMPACT_VERSION = "compact_v1"

# Fallback prompt for retry on parse failure — even simpler
TRIAGE_FALLBACK_PROMPT = """Classify this as TRUE_POSITIVE or FALSE_POSITIVE:

{title} in {file_path}:{line_start}
Code: {code_snippet_short}

Reply with exactly one JSON object:
{{"classification": "likely_true_positive", "confidence_score": 0.8, "reasoning_summary": "reason"}}"""
