# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0

"""merge multiple heads

Revision ID: 25907caaf14c
Revises: c2d3e4f5g6h7, e1f2g3h4i5j6
Create Date: 2026-04-11 19:32:28.541828
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '25907caaf14c'
down_revision: Union[str, None] = ('c2d3e4f5g6h7', 'e1f2g3h4i5j6')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
