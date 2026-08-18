# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

from __future__ import annotations
"""Quantum-vulnerable cryptographic algorithm detectors."""

from services.secret_scan.detectors.base import SecretRule

RULES: list[SecretRule] = [
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-001",
        title="RSA Key Generation (<=2048-bit) — Quantum Vulnerable",
        secret_type="quantum_vulnerable_rsa",
        severity="high",
        pattern=r'(?:RSA\.generate|rsa\.GenerateKey|RSA_generate_key|generate_private_key.*rsa\.RSA|openssl\s+genrsa)\s*[\(\s]*(?:1024|2048)',
        keywords=["RSA", "generate", "genrsa", "2048", "1024"],
        confidence=0.80,
        description="RSA key generation with 2048-bit or smaller key size. Vulnerable to quantum attack via Shor's algorithm.",
        fix_hint="Migrate to ML-DSA-65 (FIPS 204) for signatures or ML-KEM-768 (FIPS 203) for key exchange. Use hybrid RSA+ML-DSA during transition.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-002",
        title="ECDSA P-256 Curve — Quantum Vulnerable",
        secret_type="quantum_vulnerable_ecdsa",
        severity="high",
        pattern=r'(?:ECDSA|ec\.SECP256R1|P-256|prime256v1|secp256r1|NIST\s*P-256)',
        keywords=["ECDSA", "P-256", "secp256r1", "prime256v1", "SECP256R1"],
        # Calibrated 2026-04-25: 1/41 TP (2%) on gold-validated data.
        # QUANTUM-* rules flag use of quantum-vulnerable algorithms — they
        # are CRYPTO-AGILITY ADVISORIES rather than leaked credentials.
        # Even with the site-packages exclusion, the rule still fires on
        # legitimate `ec.SECP256R1()` calls in customer code that has
        # not yet migrated to PQ-safe algorithms — which is everyone.
        # Lowered confidence so these surface as informational rather
        # than as critical findings. Original: 0.75.
        confidence=0.40,
        description="ECDSA with P-256 curve. All classical elliptic curve cryptography is vulnerable to quantum attack.",
        fix_hint="Replace with ML-DSA-65 (FIPS 204) for digital signatures. SLH-DSA is a conservative alternative.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-003",
        title="DSA Key Generation — Quantum Vulnerable",
        secret_type="quantum_vulnerable_dsa",
        severity="high",
        pattern=r'(?:DSA\.generate|dsa\.GenerateKey|DSA_generate|generate_private_key.*dsa\.DSA)',
        keywords=["DSA", "generate"],
        confidence=0.85,
        description="DSA key generation detected. DSA is based on the discrete logarithm problem which is solved by quantum computers.",
        fix_hint="DSA is obsolete and quantum-vulnerable. Replace with ML-DSA-44 (FIPS 204).",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-004",
        title="Diffie-Hellman Small Parameters — Quantum Vulnerable",
        secret_type="quantum_vulnerable_dh",
        severity="medium",
        pattern=r'(?:DH\.generate|generate_parameters.*dh\.DHParameters|dh_param\s*(?:1024|2048))',
        keywords=["DH", "generate_parameters", "dh_param"],
        confidence=0.75,
        description="Diffie-Hellman key exchange with small parameters. Vulnerable to quantum attack via Shor's algorithm.",
        fix_hint="Migrate to ML-KEM-768 (FIPS 203) for key exchange. Use hybrid X25519+ML-KEM during transition.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-005",
        title="ECDH Vulnerable Curves — Quantum Vulnerable",
        secret_type="quantum_vulnerable_ecdh",
        severity="high",
        pattern=r'(?:ECDH|ecdh\.ECDH|X25519|x25519|ec\.SECP384R1|secp384r1)',
        keywords=["ECDH", "X25519", "secp384r1"],
        # Calibrated 2026-04-25: 0/13 TP on gold-validated data.
        # Same crypto-agility advisory rationale as QUANTUM-002.
        # Original: 0.75.
        confidence=0.40,
        description="Elliptic Curve Diffie-Hellman key exchange. All classical EC key exchange is quantum-vulnerable.",
        fix_hint="Replace with ML-KEM-768 (FIPS 203). Use hybrid X25519+ML-KEM-768 for transition.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-006",
        title="Ed25519 Usage — Quantum Vulnerable",
        secret_type="quantum_vulnerable_ed25519",
        severity="medium",
        pattern=r'(?:Ed25519|ed25519|ED25519_KEY|ssh-ed25519)',
        keywords=["Ed25519", "ed25519", "ssh-ed25519"],
        confidence=0.70,
        description="Ed25519 signing detected. While strong classically, Ed25519 is quantum-vulnerable.",
        fix_hint="Plan migration to ML-DSA-44 (FIPS 204). Use hybrid Ed25519+ML-DSA during transition period.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-007",
        title="Small RSA in OpenSSL Commands — Quantum Vulnerable",
        secret_type="quantum_vulnerable_openssl_rsa",
        severity="high",
        pattern=r'openssl\s+(?:genrsa|req\s+.*-newkey\s+rsa:)\s*(?:1024|2048)',
        keywords=["openssl", "genrsa", "newkey", "rsa"],
        confidence=0.85,
        description="OpenSSL command generating RSA keys with small key size. Vulnerable to quantum computers.",
        fix_hint="Use at minimum RSA-4096 for near-term safety. Plan migration to ML-DSA or ML-KEM.",
        cwe="CWE-327",
    ),
    SecretRule(
        rule_id="VOODA-SEC-QUANTUM-008",
        title="Weak TLS Cipher Suite — Quantum Vulnerable",
        secret_type="quantum_vulnerable_tls",
        severity="medium",
        pattern=r'(?:TLS_RSA_WITH|TLS_ECDHE_RSA|TLS_ECDHE_ECDSA|ssl\.PROTOCOL_TLSv1[_.]?[012]?)',
        keywords=["TLS_RSA", "TLS_ECDHE", "ssl.PROTOCOL"],
        # Calibrated 2026-04-25: 0/15 TP on gold-validated data.
        # Same crypto-agility advisory rationale as QUANTUM-002.
        # Original: 0.70.
        confidence=0.40,
        description="TLS cipher suite using quantum-vulnerable key exchange or authentication algorithms.",
        fix_hint="Configure TLS to support hybrid PQ/classical cipher suites when available. Monitor IETF PQ TLS drafts.",
        cwe="CWE-327",
    ),
]
