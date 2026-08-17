"""Pattern-database / detector-corpus file gating (2026-06-14).

Files like secrets-patterns-db's db/rules-stable.yml, a gitleaks.toml, or any
secret-scanning-custom-patterns YAML are *definitions of detection patterns* --
every line is a name:/regex:/[[rules]] entry, not a live credential. They are
dense in provider keywords and example tokens, so GENERIC proximity rules misfire
en masse there (opus x vooda benchmark: 0 TP, many FP).

_generic_lowsignal_file now treats such corpora as low-signal and drops GENERIC
matches. This is recall-safe and must remain so: an anchored SPECIFIC rule (e.g.
the AWS AKIA id rule) still fires even inside a pattern database.
"""
from services.secret_scan.engine import (
    SecretScanner,
    _pattern_db_file,
    _generic_lowsignal_file,
    _is_generic_rule,
)

_scanner = SecretScanner()

# 30 pattern definitions -> unambiguous detector corpus by content shape.
_DB_DEFS = "".join(
    f"  - pattern:\n      name: rule_{i}\n      regex: foo_{i}[_-]?token\n" for i in range(30)
)


def test_pattern_db_classification():
    assert _pattern_db_file("db/rules-stable.yml", "name: x\n") is True          # canonical name
    assert _pattern_db_file("x/secrets-patterns-db/foo.yml", "a\n") is True       # known repo path
    assert _pattern_db_file("gitleaks.toml", "[[rules]]\n") is True               # gitleaks config
    assert _pattern_db_file("custom/anything.yml", _DB_DEFS) is True              # content shape (>=25 defs)
    # negatives -- must NOT over-classify normal files
    assert _pattern_db_file("app/config/settings.yml", "regex: foo\nname: bar\n") is False  # only 2 defs
    assert _pattern_db_file("src/auth/login.py", "API_KEY='abc'\n") is False
    assert _pattern_db_file("README.md", "some prose\n") is False


def test_pattern_db_is_lowsignal_for_generic_rules():
    assert _generic_lowsignal_file("db/rules-stable.yml", "x\n") is True
    assert _generic_lowsignal_file("custom/x.yml", _DB_DEFS) is True
    # a normal small config is NOT low-signal
    assert _generic_lowsignal_file("app/settings.yml", "regex: foo\n") is False


def test_generic_finding_gated_in_pattern_db_file():
    # A generic CONFIG-ASSIGN/GEN match fires in a normal file but is gated in a
    # pattern-DB file.
    line = 'github_token = "ghp_Rk38fjQ20fjxYz9wTbCgRm4eUaKdScFnZ7y"\n'
    normal = [f.rule_id for f in _scanner.scan_file("src/settings.py", line)]
    db = [f.rule_id for f in _scanner.scan_file("custom/my-detection-patterns.yml", _DB_DEFS + line)]
    generic_hits = [r for r in normal if _is_generic_rule(r)]
    assert generic_hits, "expected a generic rule to fire in the normal file"
    assert not any(r in db for r in generic_hits), "generic finding must be gated in a pattern-DB file"


def test_specific_rule_still_fires_in_pattern_db_file():
    # RECALL GUARANTEE: a real AKIA access-key id is caught by a SPECIFIC rule,
    # which must NEVER be gated -- even inside a pattern database.
    content = _DB_DEFS + "example: AKIA2E0ABCDDEFGGHIJK\n"
    ids = [f.rule_id for f in _scanner.scan_file("custom/my-detection-patterns.yml", content)]
    assert any("AWS" in r for r in ids), f"specific AWS rule must still fire in a pattern DB; got {ids}"
