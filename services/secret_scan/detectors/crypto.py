# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Cryptographic material detectors (private keys, certificates)."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-CRYPTO-001",
        title="RSA Private Key",
        secret_type="rsa_private_key",
        severity="critical",
        pattern=r'-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----',
        keywords=["BEGIN RSA PRIVATE KEY"],
        confidence=0.95,
        description="RSA private key in PEM format.",
        fix_hint="Remove from repository. Generate new key pair. Store private keys in a vault or HSM.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRYPTO-002",
        title="EC Private Key",
        secret_type="ec_private_key",
        severity="critical",
        pattern=r'-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----',
        keywords=["BEGIN EC PRIVATE KEY"],
        confidence=0.95,
        description="Elliptic Curve private key in PEM format.",
        fix_hint="Remove from repository. Generate new EC key pair. Use a key management service.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRYPTO-003",
        title="PGP Private Key Block",
        secret_type="pgp_private_key",
        severity="critical",
        pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----',
        keywords=["BEGIN PGP PRIVATE KEY BLOCK"],
        confidence=0.95,
        description="PGP/GPG private key block.",
        fix_hint="Revoke the PGP key. Generate a new key pair. Never commit private keys.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRYPTO-004",
        title="SSH Private Key (OpenSSH)",
        secret_type="ssh_private_key",
        severity="critical",
        pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----',
        keywords=["BEGIN OPENSSH PRIVATE KEY"],
        confidence=0.95,
        description="OpenSSH private key.",
        fix_hint="Remove and generate new SSH key pair with `ssh-keygen`. Update authorized_keys on all servers.",
        multiline=True,
    ),
    SecretRule(
        rule_id="VOODA-SEC-CRYPTO-005",
        title="PKCS8 Private Key",
        secret_type="pkcs8_private_key",
        severity="critical",
        pattern=r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----',
        keywords=["BEGIN PRIVATE KEY"],
        confidence=0.90,
        description="PKCS#8 encoded private key.",
        fix_hint="Remove from repository. Regenerate the key pair. Use a secret manager.",
        multiline=True,
    ),
    # VOODA-SEC-CRYPTO-006 (X.509 Certificate) intentionally REMOVED.
    # A bare X.509 certificate is PUBLIC by design — it's the public half of the
    # keypair, handed to every TLS client during the handshake — so reporting it
    # as a finding is noise/FP, and mainstream scanners (gitleaks, TruffleHog)
    # don't flag bare certs either. The actual risk, a paired PRIVATE key, is
    # still caught by CRYPTO-001..005 (including base64-wrapped keys via the
    # Phase-2.5 decode path). If certificate *inventory* is ever wanted, surface
    # it as a separate non-secret signal — never as a secret finding.
]
