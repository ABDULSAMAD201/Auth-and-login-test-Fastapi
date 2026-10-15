"""
Create parking spaces table.

Revision ID: 0004_create_parking_spaces
Revises: 0003_create_parking_lots
Create Date: 2026-10-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_create_parking_spaces"
down_revision: Union[str, None] = "0003_create_parking_lots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "parking_spaces",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "lot_id",
            sa.Integer(),
            sa.ForeignKey("parking_lots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_unique_constraint(
        "uq_parking_space_lot_name",
        "parking_spaces",
        ["lot_id", "name"],
    )


def downgrade() -> None:
    op.drop_table("parking_spaces")
