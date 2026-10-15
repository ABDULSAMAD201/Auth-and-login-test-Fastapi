"""
Add user role column.

Revision ID: 0002_add_user_role
Revises: 0001_create_users
Create Date: 2026-10-15
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_add_user_role"
down_revision: Union[str, None] = "0001_create_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "role",
            sa.Text(),
            nullable=True,
        ),
    )
    op.execute("UPDATE users SET role = 'customer' WHERE role IS NULL")
    op.alter_column(
        "users",
        "role",
        existing_type=sa.Text(),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_column("users", "role")
