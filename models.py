from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import DateTime, ForeignKey, Integer, Text, Index, text
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql.schema import UniqueConstraint


def is_space_available(space: ParkingSpace) -> bool:
    """True when the space has no open (Pending/Active) bookings."""
    return get_space_status(space)[0] is None


def is_space_available_for_capacity(lot: ParkingLot, db: Session) -> bool:
    """True when adding one more space to lot would not exceed capacity."""
    existing_count = db.scalar(
        select(func.count()).select_from(ParkingSpace).where(
            ParkingSpace.lot_id == lot.id
        )
    )
    count = int(existing_count) if existing_count is not None else 0
    return count + 1 <= lot.capacity



class Base(DeclarativeBase):
    pass


class BookingStatus(str, Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
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
    role: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("customer"),
    )


class ParkingLot(Base):
    __tablename__ = "parking_lots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[str] = mapped_column(Text, nullable=False)
    capacity: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    spaces: Mapped[list["ParkingSpace"]] = relationship(
        back_populates="lot", order_by="ParkingSpace.id"
    )


class ParkingSpace(Base):
    __tablename__ = "parking_spaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    lot_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("parking_lots.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    lot: Mapped["ParkingLot"] = relationship(back_populates="spaces")
    bookings: Mapped[list["Booking"]] = relationship(
        back_populates="space", order_by="Booking.id"
    )

    __table_args__ = (
        UniqueConstraint("lot_id", "name", name="uq_parking_space_lot_name"),
    )


class Booking(Base):
    __tablename__ = "bookings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    space_id: Mapped[int] = mapped_column(
        ForeignKey("parking_spaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[BookingStatus] = mapped_column(
        Text,
        nullable=False,
        server_default=text("Pending"),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    space: Mapped["ParkingSpace"] = relationship(back_populates="bookings")

    __table_args__ = (
        Index(
            "ix_bookings_space_status",
            "space_id",
            "status",
        ),
    )


def get_space_status(space: ParkingSpace) -> tuple[BookingStatus | None, str]:
    """Return (open_status_or_none, color).

    Pending/Active are open bookings. Completed/Cancelled do not block a space.
    """
    open_status: BookingStatus | None = None
    for booking in space.bookings:
        if booking.status in (BookingStatus.PENDING, BookingStatus.ACTIVE):
            open_status = booking.status
            break
    if open_status == BookingStatus.PENDING:
        color = "yellow"
    elif open_status == BookingStatus.ACTIVE:
        color = "red"
    else:
        color = "green"
    return open_status, color
