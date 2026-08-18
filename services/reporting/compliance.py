# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""
Compliance mappers -- map findings to compliance frameworks.

Supports: OWASP Top 10, CWE Top 25, PCI DSS 4.0, NIST 800-53,
          ISO 27001, HIPAA, GDPR, SOC 2, CAPEC attack patterns.
"""

from typing import Optional

# ================================================================
#  OWASP Top 10 (2021)
# ================================================================

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "cwes": [
            "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201",
            "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285",
            "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441",
            "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566",
            "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862",
            "CWE-863", "CWE-913", "CWE-922", "CWE-1275",
        ],
        "keywords": ["access control", "authorization", "path traversal", "csrf", "idor", "privilege"],
    },
    "A02": {
        "name": "Cryptographic Failures",
        "cwes": [
            "CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322",
            "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328",
            "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337",
            "CWE-338", "CWE-339", "CWE-340", "CWE-347", "CWE-523", "CWE-720",
            "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916",
        ],
        "keywords": ["crypto", "hash", "md5", "sha1", "weak", "ssl", "tls", "certificate"],
    },
    "A03": {
        "name": "Injection",
        "cwes": [
            "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79",
            "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90",
            "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97",
            "CWE-98", "CWE-99", "CWE-113", "CWE-116", "CWE-138", "CWE-184",
            "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644",
            "CWE-652", "CWE-917",
        ],
        "keywords": ["injection", "sql", "xss", "command", "ldap", "xpath", "template"],
    },
    "A04": {
        "name": "Insecure Design",
        "cwes": [
            "CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256",
            "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312",
            "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444",
            "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539",
            "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650",
            "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840",
            "CWE-841", "CWE-927", "CWE-1021", "CWE-1173",
        ],
        "keywords": ["design", "business logic", "race condition", "trust boundary"],
    },
    "A05": {
        "name": "Security Misconfiguration",
        "cwes": [
            "CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260",
            "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547",
            "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004",
            "CWE-1032", "CWE-1174",
        ],
        "keywords": ["misconfiguration", "debug", "default", "xxe", "cors", "header"],
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "cwes": [],
        "keywords": ["dependency", "component", "library", "outdated", "cve"],
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "cwes": [
            "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
            "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306",
            "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
            "CWE-640", "CWE-798", "CWE-940", "CWE-1216",
        ],
        "keywords": ["authentication", "session", "credential", "password", "brute force", "hardcoded"],
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "cwes": [
            "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565",
            "CWE-784", "CWE-829", "CWE-830", "CWE-915",
        ],
        "keywords": ["deserialization", "integrity", "supply chain", "ci/cd"],
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "cwes": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "keywords": ["logging", "monitoring", "audit", "log injection"],
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwes": ["CWE-918"],
        "keywords": ["ssrf", "server-side request"],
    },
}


def map_to_owasp(cwe: Optional[str], category: str = "") -> Optional[dict]:
    """Map a finding to its OWASP Top 10 category."""
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for code, info in OWASP_TOP_10.items():
        if cwe_upper in info["cwes"]:
            return {"code": code, "name": info["name"]}
        for keyword in info["keywords"]:
            if keyword in cat_lower:
                return {"code": code, "name": info["name"]}
    return None


# ================================================================
#  CWE Top 25 (2023)
# ================================================================

CWE_TOP_25 = [
    {"rank": 1,  "cwe": "CWE-787", "name": "Out-of-bounds Write"},
    {"rank": 2,  "cwe": "CWE-79",  "name": "Cross-site Scripting"},
    {"rank": 3,  "cwe": "CWE-89",  "name": "SQL Injection"},
    {"rank": 4,  "cwe": "CWE-416", "name": "Use After Free"},
    {"rank": 5,  "cwe": "CWE-78",  "name": "OS Command Injection"},
    {"rank": 6,  "cwe": "CWE-20",  "name": "Improper Input Validation"},
    {"rank": 7,  "cwe": "CWE-125", "name": "Out-of-bounds Read"},
    {"rank": 8,  "cwe": "CWE-22",  "name": "Path Traversal"},
    {"rank": 9,  "cwe": "CWE-352", "name": "Cross-Site Request Forgery"},
    {"rank": 10, "cwe": "CWE-434", "name": "Unrestricted Upload"},
    {"rank": 11, "cwe": "CWE-862", "name": "Missing Authorization"},
    {"rank": 12, "cwe": "CWE-476", "name": "NULL Pointer Dereference"},
    {"rank": 13, "cwe": "CWE-287", "name": "Improper Authentication"},
    {"rank": 14, "cwe": "CWE-190", "name": "Integer Overflow"},
    {"rank": 15, "cwe": "CWE-502", "name": "Deserialization of Untrusted Data"},
    {"rank": 16, "cwe": "CWE-77",  "name": "Command Injection"},
    {"rank": 17, "cwe": "CWE-119", "name": "Buffer Overflow"},
    {"rank": 18, "cwe": "CWE-798", "name": "Hard-coded Credentials"},
    {"rank": 19, "cwe": "CWE-918", "name": "Server-Side Request Forgery"},
    {"rank": 20, "cwe": "CWE-306", "name": "Missing Authentication"},
    {"rank": 21, "cwe": "CWE-362", "name": "Race Condition"},
    {"rank": 22, "cwe": "CWE-269", "name": "Improper Privilege Management"},
    {"rank": 23, "cwe": "CWE-94",  "name": "Code Injection"},
    {"rank": 24, "cwe": "CWE-863", "name": "Incorrect Authorization"},
    {"rank": 25, "cwe": "CWE-276", "name": "Incorrect Default Permissions"},
]

CWE_TOP_25_SET = {item["cwe"] for item in CWE_TOP_25}


def is_in_cwe_top_25(cwe: Optional[str]) -> Optional[dict]:
    """Check if a CWE is in the Top 25 list."""
    if not cwe:
        return None
    cwe_upper = cwe.upper()
    for item in CWE_TOP_25:
        if item["cwe"] == cwe_upper:
            return item
    return None


# ================================================================
#  PCI DSS 4.0 Requirement 6
# ================================================================

PCI_DSS_MAPPING = {
    "6.2.1": {
        "name": "Secure software development lifecycle",
        "cwes": [],
        "keywords": [],
    },
    "6.2.4": {
        "name": "Software engineering techniques prevent attacks",
        "cwes": [
            "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-352", "CWE-918",
            "CWE-502", "CWE-77", "CWE-94", "CWE-611", "CWE-798",
        ],
        "keywords": ["injection", "xss", "csrf", "path traversal", "ssrf", "deserialization", "xxe"],
    },
    "6.3.1": {
        "name": "Security vulnerabilities identified and managed",
        "cwes": [],
        "keywords": ["vulnerability", "cve"],
    },
    "6.3.2": {
        "name": "Inventory of custom software and third-party components",
        "cwes": [],
        "keywords": ["dependency", "component", "library"],
    },
    "6.5.1": {
        "name": "Address common coding vulnerabilities in training",
        "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"],
        "keywords": ["owasp", "training"],
    },
}


def map_to_pci_dss(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to PCI DSS requirements."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for req_id, info in PCI_DSS_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"requirement": req_id, "name": info["name"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"requirement": req_id, "name": info["name"]})
                    break
    return results


# ================================================================
#  NIST 800-53 Rev 5  (Security & Privacy Controls)
# ================================================================

NIST_800_53_MAPPING = {
    "SA-11": {
        "name": "Developer Testing & Evaluation",
        "description": "Require developers to create and implement a test/evaluation plan; perform flaw remediation testing.",
        "cwes": [],
        "keywords": ["testing", "unit test", "code review"],
    },
    "SI-10": {
        "name": "Information Input Validation",
        "description": "Check the validity of information inputs to the system.",
        "cwes": [
            "CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
            "CWE-90", "CWE-91", "CWE-94", "CWE-113", "CWE-116", "CWE-138",
            "CWE-643", "CWE-917",
        ],
        "keywords": ["injection", "validation", "input", "xss", "sql", "command"],
    },
    "SI-11": {
        "name": "Error Handling",
        "description": "Generate error messages providing information necessary for corrective actions without revealing exploitable information.",
        "cwes": ["CWE-209", "CWE-532"],
        "keywords": ["error handling", "information disclosure", "stack trace", "debug"],
    },
    "SC-8": {
        "name": "Transmission Confidentiality & Integrity",
        "description": "Protect the confidentiality and integrity of transmitted information.",
        "cwes": [
            "CWE-319", "CWE-326", "CWE-327", "CWE-523",
        ],
        "keywords": ["encryption", "tls", "ssl", "plaintext", "cleartext", "http"],
    },
    "SC-12": {
        "name": "Cryptographic Key Establishment & Management",
        "description": "Establish and manage cryptographic keys when cryptography is employed.",
        "cwes": [
            "CWE-321", "CWE-322", "CWE-324", "CWE-325", "CWE-330", "CWE-338",
        ],
        "keywords": ["key management", "hardcoded key", "weak random", "crypto"],
    },
    "SC-13": {
        "name": "Cryptographic Protection",
        "description": "Implement FIPS-validated or NSA-approved cryptography.",
        "cwes": [
            "CWE-326", "CWE-327", "CWE-328", "CWE-757", "CWE-759", "CWE-760",
            "CWE-780", "CWE-916",
        ],
        "keywords": ["weak cipher", "md5", "sha1", "des", "rc4", "deprecated crypto"],
    },
    "SC-28": {
        "name": "Protection of Information at Rest",
        "description": "Protect the confidentiality and integrity of information at rest.",
        "cwes": ["CWE-311", "CWE-312", "CWE-313", "CWE-316"],
        "keywords": ["data at rest", "unencrypted", "sensitive data", "storage"],
    },
    "IA-5": {
        "name": "Authenticator Management",
        "description": "Manage information system authenticators (e.g., tokens, passwords).",
        "cwes": [
            "CWE-259", "CWE-521", "CWE-522", "CWE-798",
        ],
        "keywords": ["hardcoded password", "credential", "weak password", "secret"],
    },
    "AC-3": {
        "name": "Access Enforcement",
        "description": "Enforce approved authorizations for logical access to information and system resources.",
        "cwes": [
            "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863",
        ],
        "keywords": ["access control", "authorization", "privilege", "idor"],
    },
    "AC-6": {
        "name": "Least Privilege",
        "description": "Employ the principle of least privilege, granting only the minimum access necessary.",
        "cwes": ["CWE-250", "CWE-266", "CWE-269", "CWE-276"],
        "keywords": ["privilege escalation", "least privilege", "excessive permission"],
    },
    "AU-2": {
        "name": "Event Logging",
        "description": "Identify events that the system must be capable of logging.",
        "cwes": ["CWE-117", "CWE-223", "CWE-778"],
        "keywords": ["logging", "audit", "log injection"],
    },
    "CM-6": {
        "name": "Configuration Settings",
        "description": "Establish and document mandatory configuration settings for IT products.",
        "cwes": [
            "CWE-2", "CWE-16", "CWE-260", "CWE-611", "CWE-614", "CWE-942",
            "CWE-1004",
        ],
        "keywords": ["misconfiguration", "default config", "xxe", "cors", "cookie"],
    },
    "SI-16": {
        "name": "Memory Protection",
        "description": "Implement safeguards to protect system memory from unauthorized code execution.",
        "cwes": [
            "CWE-119", "CWE-125", "CWE-190", "CWE-416", "CWE-476", "CWE-787",
        ],
        "keywords": ["buffer overflow", "memory corruption", "use after free"],
    },
    "SA-15": {
        "name": "Development Process, Standards, and Tools",
        "description": "Require system developers to follow a documented development process.",
        "cwes": [],
        "keywords": ["supply chain", "dependency", "third party", "component"],
    },
}


def map_to_nist(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to NIST 800-53 controls."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for ctrl_id, info in NIST_800_53_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"control": ctrl_id, "name": info["name"], "description": info["description"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"control": ctrl_id, "name": info["name"], "description": info["description"]})
                    break
    return results


# ================================================================
#  ISO 27001:2022  (Annex A Controls)
# ================================================================

ISO_27001_MAPPING = {
    "A.8.25": {
        "name": "Secure Development Life Cycle",
        "description": "Rules for secure development of software and systems shall be established and applied.",
        "cwes": [],
        "keywords": ["secure development", "sdlc"],
    },
    "A.8.26": {
        "name": "Application Security Requirements",
        "description": "Information security requirements shall be identified and specified when developing or acquiring applications.",
        "cwes": [
            "CWE-20", "CWE-79", "CWE-89", "CWE-78", "CWE-352", "CWE-434",
            "CWE-502", "CWE-918",
        ],
        "keywords": ["injection", "xss", "csrf", "validation", "upload", "deserialization"],
    },
    "A.8.27": {
        "name": "Secure System Architecture & Engineering",
        "description": "Principles for engineering secure systems shall be established and applied.",
        "cwes": [
            "CWE-250", "CWE-269", "CWE-284", "CWE-862", "CWE-863",
        ],
        "keywords": ["design", "architecture", "access control", "authorization"],
    },
    "A.8.28": {
        "name": "Secure Coding",
        "description": "Secure coding principles shall be applied to software development.",
        "cwes": [
            "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-798",
        ],
        "keywords": ["code injection", "hardcoded", "insecure code", "sql"],
    },
    "A.8.9": {
        "name": "Configuration Management",
        "description": "Configurations shall be established, documented, implemented, monitored and reviewed.",
        "cwes": [
            "CWE-2", "CWE-16", "CWE-260", "CWE-611", "CWE-942",
        ],
        "keywords": ["misconfiguration", "default", "xxe", "cors"],
    },
    "A.8.24": {
        "name": "Use of Cryptography",
        "description": "Rules for effective use of cryptography shall be defined and implemented.",
        "cwes": [
            "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-759", "CWE-916",
        ],
        "keywords": ["crypto", "weak cipher", "md5", "sha1", "hash"],
    },
    "A.8.5": {
        "name": "Secure Authentication",
        "description": "Secure authentication technologies and procedures shall be established and implemented.",
        "cwes": [
            "CWE-259", "CWE-287", "CWE-306", "CWE-384", "CWE-521", "CWE-613",
            "CWE-798",
        ],
        "keywords": ["authentication", "session", "credential", "password"],
    },
    "A.5.33": {
        "name": "Protection of Records",
        "description": "Records shall be protected from loss, destruction, falsification and unauthorized access.",
        "cwes": ["CWE-117", "CWE-532"],
        "keywords": ["logging", "audit trail", "log injection"],
    },
    "A.8.12": {
        "name": "Data Leakage Prevention",
        "description": "Data leakage prevention measures shall be applied.",
        "cwes": [
            "CWE-200", "CWE-209", "CWE-312", "CWE-319", "CWE-359", "CWE-497",
            "CWE-532",
        ],
        "keywords": ["information disclosure", "data leak", "sensitive data", "exposure"],
    },
}


def map_to_iso27001(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to ISO 27001:2022 controls."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for ctrl_id, info in ISO_27001_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"control": ctrl_id, "name": info["name"], "description": info["description"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"control": ctrl_id, "name": info["name"], "description": info["description"]})
                    break
    return results


# ================================================================
#  HIPAA  (Security Rule -- Technical Safeguards)
# ================================================================

HIPAA_MAPPING = {
    "164.312(a)(1)": {
        "name": "Access Control",
        "description": "Implement technical policies and procedures to allow access only to authorized persons.",
        "cwes": [
            "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-269",
            "CWE-276",
        ],
        "keywords": ["access control", "authorization", "privilege", "idor"],
    },
    "164.312(a)(2)(iv)": {
        "name": "Encryption and Decryption",
        "description": "Implement a mechanism to encrypt and decrypt electronic protected health information.",
        "cwes": [
            "CWE-311", "CWE-312", "CWE-319", "CWE-326", "CWE-327",
        ],
        "keywords": ["encryption", "plaintext", "unencrypted", "cleartext"],
    },
    "164.312(c)(1)": {
        "name": "Integrity Controls",
        "description": "Implement policies to protect ePHI from improper alteration or destruction.",
        "cwes": [
            "CWE-345", "CWE-353", "CWE-494", "CWE-502",
        ],
        "keywords": ["integrity", "tampering", "deserialization"],
    },
    "164.312(d)": {
        "name": "Person or Entity Authentication",
        "description": "Implement procedures to verify the identity of persons seeking access to ePHI.",
        "cwes": [
            "CWE-287", "CWE-306", "CWE-384", "CWE-521", "CWE-798",
        ],
        "keywords": ["authentication", "credential", "password", "session"],
    },
    "164.312(e)(1)": {
        "name": "Transmission Security",
        "description": "Implement measures to guard against unauthorized access to ePHI being transmitted.",
        "cwes": ["CWE-319", "CWE-523"],
        "keywords": ["tls", "ssl", "plaintext", "http", "transmission"],
    },
    "164.312(b)": {
        "name": "Audit Controls",
        "description": "Implement mechanisms to record and examine activity in systems containing ePHI.",
        "cwes": ["CWE-117", "CWE-223", "CWE-778"],
        "keywords": ["logging", "audit", "monitoring"],
    },
    "164.308(a)(5)(ii)(B)": {
        "name": "Protection from Malicious Software",
        "description": "Procedures for guarding against, detecting, and reporting malicious software.",
        "cwes": [
            "CWE-78", "CWE-94", "CWE-434", "CWE-829",
        ],
        "keywords": ["malware", "code injection", "file upload", "command injection"],
    },
}


def map_to_hipaa(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to HIPAA Security Rule safeguards."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for req_id, info in HIPAA_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"requirement": req_id, "name": info["name"], "description": info["description"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"requirement": req_id, "name": info["name"], "description": info["description"]})
                    break
    return results


# ================================================================
#  GDPR  (General Data Protection Regulation)
# ================================================================

GDPR_MAPPING = {
    "Art.25": {
        "name": "Data Protection by Design and Default",
        "description": "Implement appropriate technical and organisational measures to protect personal data.",
        "cwes": [
            "CWE-311", "CWE-312", "CWE-319", "CWE-359", "CWE-497", "CWE-532",
        ],
        "keywords": ["sensitive data", "data exposure", "plaintext", "personal data", "pii"],
    },
    "Art.32(1)(a)": {
        "name": "Encryption of Personal Data",
        "description": "Pseudonymisation and encryption of personal data.",
        "cwes": [
            "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-916",
        ],
        "keywords": ["encryption", "weak cipher", "md5", "sha1", "crypto"],
    },
    "Art.32(1)(b)": {
        "name": "Confidentiality & Integrity of Processing Systems",
        "description": "Ensure ongoing confidentiality, integrity, availability and resilience of processing.",
        "cwes": [
            "CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-918",
        ],
        "keywords": ["injection", "xss", "command", "deserialization", "ssrf"],
    },
    "Art.32(1)(d)": {
        "name": "Testing & Evaluating Security Measures",
        "description": "Regularly test, assess, and evaluate effectiveness of technical measures.",
        "cwes": [],
        "keywords": ["testing", "assessment", "scanning", "audit"],
    },
    "Art.5(1)(f)": {
        "name": "Integrity and Confidentiality Principle",
        "description": "Personal data shall be processed in a manner that ensures appropriate security.",
        "cwes": [
            "CWE-200", "CWE-209", "CWE-284", "CWE-862",
        ],
        "keywords": ["information disclosure", "access control", "authorization"],
    },
    "Art.33": {
        "name": "Notification of Personal Data Breach",
        "description": "Notify supervisory authority within 72 hours of becoming aware of a breach.",
        "cwes": [],
        "keywords": ["logging", "monitoring", "detection", "breach"],
    },
}


def map_to_gdpr(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to GDPR articles."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for art_id, info in GDPR_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"article": art_id, "name": info["name"], "description": info["description"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"article": art_id, "name": info["name"], "description": info["description"]})
                    break
    return results


# ================================================================
#  SOC 2  (Trust Services Criteria)
# ================================================================

SOC2_MAPPING = {
    "CC6.1": {
        "name": "Logical & Physical Access Controls",
        "description": "Implement logical access security to protect against threats from unauthorized access.",
        "cwes": [
            "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-639", "CWE-862",
            "CWE-863",
        ],
        "keywords": ["access control", "authentication", "authorization", "idor"],
    },
    "CC6.6": {
        "name": "System Boundary Protection",
        "description": "Restrict access to system boundaries and manage data flow.",
        "cwes": [
            "CWE-20", "CWE-79", "CWE-89", "CWE-918",
        ],
        "keywords": ["injection", "xss", "sql", "ssrf", "input validation"],
    },
    "CC6.7": {
        "name": "Data Transmission Restrictions",
        "description": "Restrict transmission, movement, and removal of data.",
        "cwes": ["CWE-311", "CWE-319", "CWE-523"],
        "keywords": ["encryption", "tls", "cleartext", "http"],
    },
    "CC7.2": {
        "name": "Security Incident Monitoring",
        "description": "Monitor system components for anomalies indicating security incidents.",
        "cwes": ["CWE-117", "CWE-223", "CWE-778"],
        "keywords": ["logging", "monitoring", "audit", "detection"],
    },
    "CC8.1": {
        "name": "Change Management",
        "description": "Authorize, design, develop, configure, document, test, approve, and implement changes.",
        "cwes": [],
        "keywords": ["change management", "deployment", "ci/cd"],
    },
    "CC3.2": {
        "name": "Risk Assessment",
        "description": "Identify risks to the achievement of objectives including fraud risks.",
        "cwes": [],
        "keywords": ["vulnerability", "risk", "threat"],
    },
    "CC6.3": {
        "name": "Role-based Access & Least Privilege",
        "description": "Create/modify access based on authorization, implement least privilege and SoD.",
        "cwes": [
            "CWE-250", "CWE-266", "CWE-269", "CWE-276",
        ],
        "keywords": ["privilege", "least privilege", "role", "excessive permission"],
    },
    "CC7.1": {
        "name": "Vulnerability Detection",
        "description": "Detect vulnerabilities and evaluate against defined tolerances.",
        "cwes": [],
        "keywords": ["scanning", "vulnerability", "assessment", "sast"],
    },
}


def map_to_soc2(cwe: Optional[str], category: str = "") -> list[dict]:
    """Map a finding to SOC 2 Trust Services Criteria."""
    results = []
    cwe_upper = (cwe or "").upper()
    cat_lower = (category or "").lower()
    for cc_id, info in SOC2_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({"criteria": cc_id, "name": info["name"], "description": info["description"]})
        else:
            for keyword in info["keywords"]:
                if keyword in cat_lower:
                    results.append({"criteria": cc_id, "name": info["name"], "description": info["description"]})
                    break
    return results


# ================================================================
#  CAPEC  (Common Attack Pattern Enumeration & Classification)
# ================================================================

CAPEC_MAPPING = {
    "CAPEC-66": {
        "name": "SQL Injection",
        "description": "Attacker injects SQL commands via application input to alter database queries.",
        "cwes": ["CWE-89"],
        "likelihood": "high",
        "severity": "high",
    },
    "CAPEC-86": {
        "name": "XSS via HTTP Headers",
        "description": "Attacker injects malicious content into HTTP response headers.",
        "cwes": ["CWE-79", "CWE-113"],
        "likelihood": "medium",
        "severity": "medium",
    },
    "CAPEC-88": {
        "name": "OS Command Injection",
        "description": "Attacker executes arbitrary OS commands through an application.",
        "cwes": ["CWE-78", "CWE-77"],
        "likelihood": "medium",
        "severity": "high",
    },
    "CAPEC-126": {
        "name": "Path Traversal",
        "description": "Attacker manipulates file paths to access files outside intended directory.",
        "cwes": ["CWE-22", "CWE-23", "CWE-35"],
        "likelihood": "high",
        "severity": "high",
    },
    "CAPEC-62": {
        "name": "Cross-Site Request Forgery",
        "description": "Attacker tricks authenticated user into performing unintended actions.",
        "cwes": ["CWE-352"],
        "likelihood": "medium",
        "severity": "medium",
    },
    "CAPEC-242": {
        "name": "Code Injection",
        "description": "Attacker introduces code that gets executed by the application.",
        "cwes": ["CWE-94", "CWE-95", "CWE-96"],
        "likelihood": "medium",
        "severity": "high",
    },
    "CAPEC-664": {
        "name": "Server-Side Request Forgery",
        "description": "Attacker induces server to make requests to an unintended destination.",
        "cwes": ["CWE-918"],
        "likelihood": "medium",
        "severity": "high",
    },
    "CAPEC-586": {
        "name": "Object Injection",
        "description": "Attacker provides specially crafted serialized objects to trigger code execution.",
        "cwes": ["CWE-502"],
        "likelihood": "medium",
        "severity": "high",
    },
    "CAPEC-112": {
        "name": "Brute Force",
        "description": "Attacker attempts exhaustive credential guessing to gain unauthorized access.",
        "cwes": ["CWE-307", "CWE-521"],
        "likelihood": "high",
        "severity": "medium",
    },
    "CAPEC-560": {
        "name": "Use of Known Domain Credentials",
        "description": "Attacker uses known default/hardcoded credentials to access a system.",
        "cwes": ["CWE-798", "CWE-259"],
        "likelihood": "high",
        "severity": "high",
    },
    "CAPEC-17": {
        "name": "Using Malicious Files",
        "description": "Attacker uploads malicious file to execute code on the server.",
        "cwes": ["CWE-434"],
        "likelihood": "medium",
        "severity": "high",
    },
    "CAPEC-153": {
        "name": "Input Data Manipulation",
        "description": "Attacker alters input data to cause unintended consequences.",
        "cwes": ["CWE-20"],
        "likelihood": "high",
        "severity": "medium",
    },
    "CAPEC-221": {
        "name": "Data Serialization External Entities",
        "description": "Attacker exploits XML external entity processing to access files or services.",
        "cwes": ["CWE-611"],
        "likelihood": "medium",
        "severity": "high",
    },
}


def map_to_capec(cwe: Optional[str]) -> list[dict]:
    """Map a CWE to CAPEC attack patterns."""
    if not cwe:
        return []
    results = []
    cwe_upper = cwe.upper()
    for capec_id, info in CAPEC_MAPPING.items():
        if cwe_upper in info["cwes"]:
            results.append({
                "id": capec_id,
                "name": info["name"],
                "description": info["description"],
                "likelihood": info["likelihood"],
                "severity": info["severity"],
            })
    return results


# ================================================================
#  Aggregate Compliance Summary  (All Frameworks)
# ================================================================

def _severity_bucket() -> dict:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def generate_compliance_summary(findings: list[dict]) -> dict:
    """
    Generate a compliance summary across ALL frameworks for a set of findings.

    Args:
        findings: List of dicts with 'cwe', 'vulnerability_category', and optional 'severity' keys.

    Returns:
        Dict with OWASP, CWE Top 25, PCI DSS, NIST, ISO 27001, HIPAA, GDPR, SOC 2 breakdowns.
    """
    owasp_counts: dict[str, int] = {}
    owasp_severity: dict[str, dict[str, int]] = {}
    cwe_top25_matches = []
    pci_reqs: dict[str, int] = {}
    pci_severity: dict[str, dict[str, int]] = {}
    nist_ctrls: dict[str, int] = {}
    nist_severity: dict[str, dict[str, int]] = {}
    iso_ctrls: dict[str, int] = {}
    iso_severity: dict[str, dict[str, int]] = {}
    hipaa_reqs: dict[str, int] = {}
    hipaa_severity: dict[str, dict[str, int]] = {}
    gdpr_arts: dict[str, int] = {}
    gdpr_severity: dict[str, dict[str, int]] = {}
    soc2_criteria: dict[str, int] = {}
    soc2_severity: dict[str, dict[str, int]] = {}
    capec_attacks: dict[str, int] = {}

    for f in findings:
        cwe = f.get("cwe")
        category = f.get("vulnerability_category", "")
        severity = f.get("severity", "medium")

        # OWASP
        owasp = map_to_owasp(cwe, category)
        if owasp:
            key = f"{owasp['code']}: {owasp['name']}"
            owasp_counts[key] = owasp_counts.get(key, 0) + 1
            if key not in owasp_severity:
                owasp_severity[key] = _severity_bucket()
            if severity in owasp_severity[key]:
                owasp_severity[key][severity] += 1

        # CWE Top 25
        cwe_match = is_in_cwe_top_25(cwe)
        if cwe_match:
            cwe_top25_matches.append(cwe_match)

        # PCI DSS
        pci = map_to_pci_dss(cwe, category)
        for req in pci:
            key = f"{req['requirement']}: {req['name']}"
            pci_reqs[key] = pci_reqs.get(key, 0) + 1
            if key not in pci_severity:
                pci_severity[key] = _severity_bucket()
            if severity in pci_severity[key]:
                pci_severity[key][severity] += 1

        # NIST 800-53
        nist = map_to_nist(cwe, category)
        for ctrl in nist:
            key = f"{ctrl['control']}: {ctrl['name']}"
            nist_ctrls[key] = nist_ctrls.get(key, 0) + 1
            if key not in nist_severity:
                nist_severity[key] = _severity_bucket()
            if severity in nist_severity[key]:
                nist_severity[key][severity] += 1

        # ISO 27001
        iso = map_to_iso27001(cwe, category)
        for ctrl in iso:
            key = f"{ctrl['control']}: {ctrl['name']}"
            iso_ctrls[key] = iso_ctrls.get(key, 0) + 1
            if key not in iso_severity:
                iso_severity[key] = _severity_bucket()
            if severity in iso_severity[key]:
                iso_severity[key][severity] += 1

        # HIPAA
        hipaa = map_to_hipaa(cwe, category)
        for req in hipaa:
            key = f"{req['requirement']}: {req['name']}"
            hipaa_reqs[key] = hipaa_reqs.get(key, 0) + 1
            if key not in hipaa_severity:
                hipaa_severity[key] = _severity_bucket()
            if severity in hipaa_severity[key]:
                hipaa_severity[key][severity] += 1

        # GDPR
        gdpr = map_to_gdpr(cwe, category)
        for art in gdpr:
            key = f"{art['article']}: {art['name']}"
            gdpr_arts[key] = gdpr_arts.get(key, 0) + 1
            if key not in gdpr_severity:
                gdpr_severity[key] = _severity_bucket()
            if severity in gdpr_severity[key]:
                gdpr_severity[key][severity] += 1

        # SOC 2
        soc2 = map_to_soc2(cwe, category)
        for crit in soc2:
            key = f"{crit['criteria']}: {crit['name']}"
            soc2_criteria[key] = soc2_criteria.get(key, 0) + 1
            if key not in soc2_severity:
                soc2_severity[key] = _severity_bucket()
            if severity in soc2_severity[key]:
                soc2_severity[key][severity] += 1

        # CAPEC
        capec = map_to_capec(cwe)
        for atk in capec:
            key = f"{atk['id']}: {atk['name']}"
            capec_attacks[key] = capec_attacks.get(key, 0) + 1

    # -- Helper to build framework detail ---
    def _build_detail(all_keys: list[str], counts: dict, sev_map: dict) -> dict:
        detail = {}
        for key in all_keys:
            count = counts.get(key, 0)
            detail[key] = {
                "count": count,
                "status": "pass" if count == 0 else "fail",
                "severity": sev_map.get(key, _severity_bucket()),
            }
        return detail

    # -- OWASP ---
    all_owasp = [f"{code}: {info['name']}" for code, info in OWASP_TOP_10.items()]
    owasp_clean = [c for c in all_owasp if c not in owasp_counts]
    owasp_score = round(len(owasp_clean) / len(all_owasp) * 100)
    owasp_detail = _build_detail(all_owasp, owasp_counts, owasp_severity)

    # -- PCI DSS ---
    all_pci = [f"{r}: {info['name']}" for r, info in PCI_DSS_MAPPING.items()]
    pci_clean = [r for r in all_pci if r not in pci_reqs]
    pci_score = round(len(pci_clean) / max(len(all_pci), 1) * 100)
    pci_detail = _build_detail(all_pci, pci_reqs, pci_severity)

    # -- CWE Top 25 ---
    unique_cwes = set(m["cwe"] for m in cwe_top25_matches)
    cwe_score = round((25 - len(unique_cwes)) / 25 * 100)

    # -- NIST ---
    all_nist = [f"{c}: {info['name']}" for c, info in NIST_800_53_MAPPING.items()]
    nist_clean = [c for c in all_nist if c not in nist_ctrls]
    nist_score = round(len(nist_clean) / max(len(all_nist), 1) * 100)
    nist_detail = _build_detail(all_nist, nist_ctrls, nist_severity)

    # -- ISO 27001 ---
    all_iso = [f"{c}: {info['name']}" for c, info in ISO_27001_MAPPING.items()]
    iso_clean = [c for c in all_iso if c not in iso_ctrls]
    iso_score = round(len(iso_clean) / max(len(all_iso), 1) * 100)
    iso_detail = _build_detail(all_iso, iso_ctrls, iso_severity)

    # -- HIPAA ---
    all_hipaa = [f"{r}: {info['name']}" for r, info in HIPAA_MAPPING.items()]
    hipaa_clean = [r for r in all_hipaa if r not in hipaa_reqs]
    hipaa_score = round(len(hipaa_clean) / max(len(all_hipaa), 1) * 100)
    hipaa_detail = _build_detail(all_hipaa, hipaa_reqs, hipaa_severity)

    # -- GDPR ---
    all_gdpr = [f"{a}: {info['name']}" for a, info in GDPR_MAPPING.items()]
    gdpr_clean = [a for a in all_gdpr if a not in gdpr_arts]
    gdpr_score = round(len(gdpr_clean) / max(len(all_gdpr), 1) * 100)
    gdpr_detail = _build_detail(all_gdpr, gdpr_arts, gdpr_severity)

    # -- SOC 2 ---
    all_soc2 = [f"{c}: {info['name']}" for c, info in SOC2_MAPPING.items()]
    soc2_clean = [c for c in all_soc2 if c not in soc2_criteria]
    soc2_score = round(len(soc2_clean) / max(len(all_soc2), 1) * 100)
    soc2_detail = _build_detail(all_soc2, soc2_criteria, soc2_severity)

    return {
        # OWASP
        "owasp_top_10": owasp_detail,
        "owasp_score": owasp_score,
        "owasp_categories_clean": len(owasp_clean),
        "owasp_categories_total": len(all_owasp),
        # CWE Top 25
        "cwe_top_25_matches": len(unique_cwes),
        "cwe_top_25_score": cwe_score,
        "cwe_top_25_findings": cwe_top25_matches,
        # PCI DSS
        "pci_dss": pci_detail,
        "pci_dss_score": pci_score,
        "pci_dss_requirements_clean": len(pci_clean),
        "pci_dss_requirements_total": len(all_pci),
        # NIST 800-53
        "nist_800_53": nist_detail,
        "nist_score": nist_score,
        "nist_controls_clean": len(nist_clean),
        "nist_controls_total": len(all_nist),
        # ISO 27001
        "iso_27001": iso_detail,
        "iso_score": iso_score,
        "iso_controls_clean": len(iso_clean),
        "iso_controls_total": len(all_iso),
        # HIPAA
        "hipaa": hipaa_detail,
        "hipaa_score": hipaa_score,
        "hipaa_requirements_clean": len(hipaa_clean),
        "hipaa_requirements_total": len(all_hipaa),
        # GDPR
        "gdpr": gdpr_detail,
        "gdpr_score": gdpr_score,
        "gdpr_articles_clean": len(gdpr_clean),
        "gdpr_articles_total": len(all_gdpr),
        # SOC 2
        "soc2": soc2_detail,
        "soc2_score": soc2_score,
        "soc2_criteria_clean": len(soc2_clean),
        "soc2_criteria_total": len(all_soc2),
        # CAPEC
        "capec_attack_patterns": capec_attacks,
        "capec_patterns_matched": len(capec_attacks),
        # Meta
        "total_findings": len(findings),
        "frameworks_assessed": 8,
    }


def generate_per_finding_compliance(cwe: Optional[str], category: str = "") -> dict:
    """Generate full compliance mapping for a single finding (used in developer/detail reports)."""
    return {
        "owasp": map_to_owasp(cwe, category),
        "cwe_top_25": is_in_cwe_top_25(cwe),
        "pci_dss": map_to_pci_dss(cwe, category),
        "nist_800_53": map_to_nist(cwe, category),
        "iso_27001": map_to_iso27001(cwe, category),
        "hipaa": map_to_hipaa(cwe, category),
        "gdpr": map_to_gdpr(cwe, category),
        "soc2": map_to_soc2(cwe, category),
        "capec": map_to_capec(cwe),
    }
