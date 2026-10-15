from sqlalchemy import Integer, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(Text, primary_key=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    reset_token_hash: Mapped[str | None] = mapped_column(Text)
    reset_expires_at: Mapped[int | None] = mapped_column(Integer)
    full_name: Mapped[str | None] = mapped_column(Text)
    phone: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str | None] = mapped_column(Text)
    terms_accepted_at: Mapped[int | None] = mapped_column(Integer)
    failed_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    locked_until: Mapped[int | None] = mapped_column(Integer)
    session_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
