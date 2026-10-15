"""
Create bookings table.

Revision ID: 0005_create_bookings
Revises: 0004_create_parking_spaces
Create Date: 2026-10-16
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_create_bookings"
down_revision: Union[str, None] = "0004_create_parking_spaces"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bookings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Text(),
            sa.ForeignKey("users.email", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "space_id",
            sa.Integer(),
            sa.ForeignKey("parking_spaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "start_time",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "end_time",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'Pending'"),
        ),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "ended_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index(
        "ix_bookings_space_status",
        "bookings",
        ["space_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_bookings_space_status", table_name="bookings")
    op.drop_table("bookings")
