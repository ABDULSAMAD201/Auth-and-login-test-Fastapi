"""Create users table.

Revision ID: 0001_create_users
Revises:
Create Date: 2026-10-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_create_users"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.Text(), primary_key=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("reset_token_hash", sa.Text(), nullable=True),
        sa.Column("reset_expires_at", sa.Integer(), nullable=True),
        sa.Column("full_name", sa.Text(), nullable=True),
        sa.Column("phone", sa.Text(), nullable=True),
        sa.Column("state", sa.Text(), nullable=True),
        sa.Column("terms_accepted_at", sa.Integer(), nullable=True),
        sa.Column(
            "failed_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("locked_until", sa.Integer(), nullable=True),
        sa.Column(
            "session_version",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("users")
