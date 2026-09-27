"""Encrypt provider API keys already stored in the clear.

The column has been called ``api_key_encrypted`` since it was added and
held the key verbatim, with a comment in the router conceding the point
("In production, encrypt this"). Anything holding a copy of the
database — a backup, a read replica, a support dump — held the
customer's provider credential in plain text. OAuth tokens in this same
application were already encrypted, so this was an inconsistency rather
than a missing capability.

The read path accepts both forms, so this backfill can run before or
after the code that writes encrypted values, and a row written either
way keeps working.

What this protects against: a copy of the database alone. Not an
attacker holding both the database and SECRET_KEY, since the Fernet key
is derived from it. After this migration SECRET_KEY is load-bearing for
stored credentials — rotating it orphans every provider key, and they
have to be re-entered.

Revision ID: s4m5n6o7p8q9
Revises: r3l4m5n6o7p8
"""
from alembic import op
import sqlalchemy as sa

revision = "s4m5n6o7p8q9"
down_revision = "r3l4m5n6o7p8"
branch_labels = None
depends_on = None


def _rows(conn):
    return conn.execute(sa.text(
        "SELECT id, api_key_encrypted FROM ai_model_configs "
        "WHERE api_key_encrypted IS NOT NULL AND api_key_encrypted <> ''"
    )).fetchall()


def upgrade() -> None:
    from packages.common.encryption import encrypt_value

    conn = op.get_bind()
    for row in _rows(conn):
        # Idempotent: a value already encrypted is left alone, so a
        # re-run cannot double-wrap a key into something unreadable.
        if row.api_key_encrypted.startswith("enc:"):
            continue
        conn.execute(
            sa.text("UPDATE ai_model_configs SET api_key_encrypted = :v "
                    "WHERE id = :i"),
            {"v": encrypt_value(row.api_key_encrypted), "i": row.id},
        )


def downgrade() -> None:
    """Put the keys back in the clear.

    Only possible while SECRET_KEY is the one they were encrypted with.
    A value that cannot be read is left as it is rather than replaced
    with something unusable — losing a credential is worse than leaving
    a row this migration cannot undo.
    """
    from packages.common.encryption import decrypt_value

    conn = op.get_bind()
    for row in _rows(conn):
        if not row.api_key_encrypted.startswith("enc:"):
            continue
        plain = decrypt_value(row.api_key_encrypted)
        if plain == row.api_key_encrypted:
            continue  # unreadable — leave it rather than corrupt it
        conn.execute(
            sa.text("UPDATE ai_model_configs SET api_key_encrypted = :v "
                    "WHERE id = :i"),
            {"v": plain, "i": row.id},
        )
