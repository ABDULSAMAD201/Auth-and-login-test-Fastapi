"""
Create parking lots table.

Revision ID: 0003_create_parking_lots
Revises: 0002_add_user_role
Create Date: 2026-10-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_create_parking_lots"
down_revision: Union[str, None] = "0002_add_user_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "parking_lots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("location", sa.Text(), nullable=False),
        sa.Column(
            "capacity",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_table("parking_lots")
