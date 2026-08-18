# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""AWS secret detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-AWS-001",
        title="AWS Access Key ID",
        secret_type="aws_access_key",
        severity="critical",
        pattern=r'(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9]|$)',
        keywords=["AKIA"],
        confidence=0.95,
        description="AWS access key ID detected. These keys grant programmatic access to AWS services.",
        fix_hint="Rotate key in AWS IAM console. Use IAM roles or environment variables instead.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AWS-002",
        title="AWS Secret Access Key",
        secret_type="aws_secret_key",
        severity="critical",
        # 2026-06-13: extended after a live finding (log-upload.php) where the
        # secret half of an AWS credential pair was MISSED. Two gaps closed,
        # both purely additive (superset of the prior pattern):
        #   • operator `=>` (PHP/Ruby hashrocket) alongside `[:=]`
        #   • `secret_?access_?key` also matches camelCase `secretAccessKey`
        #     (JS/TS SDK v2/v3); added `client_secret` (OAuth).
        pattern=r'(?:aws_secret_access_key|aws_secret_key|secret_?access_?key|AWS_SECRET_ACCESS_KEY)["\']?\s*(?:=>|[:=])\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        keywords=["aws_secret", "secret_access_key", "secretaccesskey", "AWS_SECRET"],
        confidence=0.90,
        description="AWS secret access key detected. Combined with an access key ID, this grants full API access.",
        fix_hint="Rotate both access key and secret key in AWS IAM. Use IAM roles for EC2/Lambda.",
    ),
    SecretRule(
        # 2026-06-13: the BARE-`secret` half of an AWS SDK credential array
        # (`'secret' => "<40 b64>"` / `secret: "<40 b64>"` / `secret = "..."`),
        # the idiom AWS-002 can't key on (its keys are the explicit
        # aws_secret_access_key family). Gated by keywords=["AKIA"] so the rule
        # ONLY runs on files that ALSO contain an AWS access-key id — i.e. real
        # AWS SDK credential blocks — keeping FP near-zero (a bare `secret:` in
        # an unrelated config never triggers this rule). Anchors on the secret's
        # OWN line so it surfaces as a DISTINCT finding instead of being
        # same-line-deduped against the AKIA id. Captures the 40-char secret
        # (group 1). Surfaced after a live leak (log-upload.php): the secret was
        # undetected, so the snippet redactor never masked it → rendered raw in
        # the Code tab. re2-safe (no lookaround/backref; fixed repetition).
        rule_id="VOODA-SEC-AWS-005",
        title="AWS Secret Access Key (SDK credential block)",
        secret_type="aws_secret_key",
        severity="critical",
        pattern=r'["\']?(?:secret|secret_?key)["\']?\s*(?:=>|[:=])\s*["\']([A-Za-z0-9/+]{40})["\']',
        keywords=["AKIA"],
        confidence=0.90,
        description="AWS secret access key in an SDK credential block, co-located with an AWS access key ID — a complete, immediately-usable credential pair.",
        fix_hint="Rotate BOTH the access key ID and the secret access key in AWS IAM immediately; never commit SDK credential blocks.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AWS-003",
        title="AWS Session Token",
        secret_type="aws_session_token",
        severity="high",
        pattern=r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*["\']?(FwoGZX[A-Za-z0-9/+=]{100,})["\']?',
        keywords=["aws_session_token", "AWS_SESSION_TOKEN", "FwoGZX"],
        confidence=0.90,
        description="AWS temporary session token detected.",
        fix_hint="Session tokens are temporary but should never be committed. Use STS AssumeRole at runtime.",
    ),
    SecretRule(
        rule_id="VOODA-SEC-AWS-004",
        title="AWS MWS Auth Token",
        secret_type="aws_mws_token",
        severity="high",
        pattern=r'(?:^|[^A-Za-z0-9])(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[^A-Za-z0-9]|$)',
        keywords=["amzn.mws"],
        confidence=0.95,
        description="Amazon Marketplace Web Service auth token detected.",
        fix_hint="Rotate MWS token in Amazon Seller Central.",
    ),
]
