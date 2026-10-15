"""Booking integrity constraints and indexes.

Adds the index on bookings.user_id declared by the model, a partial unique
index that stops a parking space from holding more than one open
(Pending/Active) booking, and the database default for users.role.

Revision ID: 0006_booking_indexes
Revises: 0005_create_bookings
Create Date: 2026-10-16
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_booking_indexes"
down_revision: Union[str, None] = "0005_create_bookings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OPEN_BOOKING_PREDICATE = "status IN ('Pending', 'Active')"


def upgrade() -> None:
    op.create_index(
        "ix_bookings_user_id",
        "bookings",
        ["user_id"],
    )
    # A partial unique index is supported by both PostgreSQL and SQLite, so a
    # space can only ever have one open booking even under concurrency. The
    # application additionally locks the space row inside a transaction.
    op.create_index(
        "uq_bookings_open_space",
        "bookings",
        ["space_id"],
        unique=True,
        postgresql_where=sa.text(OPEN_BOOKING_PREDICATE),
        sqlite_where=sa.text(OPEN_BOOKING_PREDICATE),
    )
    # Keep the database default in step with the model so existing rows and
    # new inserts both receive the customer role.
    op.alter_column(
        "users",
        "role",
        existing_type=sa.Text(),
        existing_nullable=False,
        server_default=sa.text("'customer'"),
    )


def downgrade() -> None:
    op.alter_column(
        "users",
        "role",
        existing_type=sa.Text(),
        existing_nullable=False,
        server_default=None,
    )
    op.drop_index("uq_bookings_open_space", table_name="bookings")
    op.drop_index("ix_bookings_user_id", table_name="bookings")
