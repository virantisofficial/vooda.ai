"""The three defects that blocked a production deployment.

Each of these shipped, each is the kind of thing a security product
gets held to a higher standard on, and none of them had a test.
"""

import os
import subprocess
import sys
import time

import pytest

from apps.api.app.core.config import (
    _MIN_SECRET_KEY_LENGTH,
    _UNSAFE_SECRET_KEYS,
    assert_production_secret_key,
    settings,
)
from apps.api.app.core.security import verify_password_constant_time, hash_password


# ── 1. SECRET_KEY must not be guessable in production ─────────────
@pytest.mark.parametrize("bad", sorted(_UNSAFE_SECRET_KEYS) + ["short", "a" * 31])
def test_production_refuses_a_weak_secret_key(bad, monkeypatch):
    """A weak key is not a warning — it is a refusal to start.

    SECRET_KEY signs sessions and encrypts every stored integration
    credential. docker-compose passes `${SECRET_KEY}`, so an operator
    who never set it got an empty string, and the app started and
    encrypted Vault tokens with a key derivable from this repository.
    """
    monkeypatch.setenv("VOODA_ENV", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", bad)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        assert_production_secret_key()


def test_the_error_says_how_to_fix_it(monkeypatch):
    monkeypatch.setenv("VOODA_ENV", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "")
    with pytest.raises(RuntimeError) as e:
        assert_production_secret_key()
    assert "openssl rand -hex 32" in str(e.value)


def test_a_strong_key_is_accepted(monkeypatch):
    monkeypatch.setenv("VOODA_ENV", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "a" * _MIN_SECRET_KEY_LENGTH)
    assert_production_secret_key()


def test_non_production_only_warns(monkeypatch):
    """Local dev and pytest must keep working without a real key."""
    monkeypatch.setenv("VOODA_ENV", "development")
    monkeypatch.setattr(settings, "SECRET_KEY", "")
    assert_production_secret_key()   # must not raise


def test_production_is_the_default_when_env_is_unset(monkeypatch):
    """Forgetting VOODA_ENV must fail closed, not open."""
    monkeypatch.delenv("VOODA_ENV", raising=False)
    monkeypatch.setattr(settings, "SECRET_KEY", "")
    with pytest.raises(RuntimeError):
        assert_production_secret_key()


# ── 2. Login must not reveal which accounts exist ─────────────────
def _median_ms(fn, runs: int = 5) -> float:
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return sorted(times)[len(times) // 2]


def test_unknown_user_costs_the_same_as_a_wrong_password():
    """The timing gap was the enumeration oracle.

    Skipping bcrypt for a missing account answered "does this account
    exist?" in the response time — about 20ms versus 340ms — so an
    attacker could map every account without a valid credential.

    Asserts on a ratio, not absolute milliseconds, so it stays
    meaningful on slower CI hardware. The tolerance is wide because
    bcrypt timing is noisy; the bug being caught was a 17x gap.
    """
    real = hash_password("the-real-password")

    known = _median_ms(lambda: verify_password_constant_time("wrong", real))
    unknown = _median_ms(lambda: verify_password_constant_time("wrong", None))

    ratio = max(known, unknown) / max(min(known, unknown), 0.001)
    assert ratio < 3, (
        f"login timing distinguishes a real account from an unknown one "
        f"({known:.0f}ms vs {unknown:.0f}ms, {ratio:.1f}x) — that is a "
        f"user-enumeration oracle"
    )


def test_unknown_user_still_fails():
    assert verify_password_constant_time("anything", None) is False


def test_a_correct_password_still_authenticates():
    h = hash_password("correct-horse")
    assert verify_password_constant_time("correct-horse", h) is True
    assert verify_password_constant_time("wrong-horse", h) is False


# ── 3. No default credentials ─────────────────────────────────────
def test_seed_has_no_hardcoded_admin_password():
    """`Adwin@123` was the admin password on every install that did not
    override it — a documented credential on an internet-facing
    security product."""
    src = open("infra/scripts/seed.py").read()
    body = src.split('"""', 2)[-1]          # ignore the docstring's history note
    assert "Adwin@123" not in body
    assert 'os.environ.get("SEED_ADMIN_PASSWORD")' in body


def test_seed_generates_a_strong_password_when_none_is_given():
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0,'.');"
         "from infra.scripts.seed import _generate_password as g;"
         "print(g()); print(g())"],
        capture_output=True, text=True, env={**os.environ, "DATABASE_URL_SYNC": "postgresql://x/y"},
    )
    assert out.returncode == 0, out.stderr
    a, b = out.stdout.split()
    assert len(a) >= 24
    assert a != b, "generated passwords must not repeat"
    assert not set("O0lI1") & set(a), "ambiguous characters make a printed password unusable"
