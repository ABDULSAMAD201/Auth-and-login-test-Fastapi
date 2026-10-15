from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class BookingStatus(str, Enum):
    PENDING = "Pending"
    ACTIVE = "Active"
    COMPLETED = "Completed"
    CANCELLED = "Cancelled"


#: Statuses that keep a parking space occupied.
OPEN_BOOKING_STATUSES = (BookingStatus.PENDING, BookingStatus.ACTIVE)

#: Displayed colour for each open booking status. Spaces without an open
#: booking are green.
STATUS_COLORS = {
    BookingStatus.PENDING: "yellow",
    BookingStatus.ACTIVE: "red",
}
AVAILABLE_COLOR = "green"


def now_utc() -> datetime:
    """Current time as a timezone-aware UTC datetime.

    Every booking timestamp in the application is stored in UTC; the only
    conversion happens when the browser renders a ``datetime-local`` value.
    """
    return datetime.now(timezone.utc)


class BookingStatusType(TypeDecorator):
    """Persist :class:`BookingStatus` as plain text, return enum members.

    Keeping the column as text preserves the existing schema while letting the
    application compare against ``BookingStatus`` members directly.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: object, dialect) -> str | None:
        if value is None:
            return None
        if isinstance(value, BookingStatus):
            return value.value
        return BookingStatus(str(value)).value

    def process_result_value(self, value: object, dialect) -> BookingStatus | None:
        if value is None:
            return None
        if isinstance(value, BookingStatus):
            return value
        return BookingStatus(str(value))


class User(Base):
    __tablename__ = "users"

    # The users table uses the email address as its primary key; this mirrors
    # the existing production schema and keeps existing accounts intact.
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
    role: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("'customer'"),
    )

    bookings: Mapped[list["Booking"]] = relationship(
        back_populates="user", order_by="Booking.id", cascade="all, delete-orphan"
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
    # References the User primary key (the account email address).
    user_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("users.email", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    space_id: Mapped[int] = mapped_column(
        ForeignKey("parking_spaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    status: Mapped[BookingStatus] = mapped_column(
        BookingStatusType,
        nullable=False,
        server_default=text("'Pending'"),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    user: Mapped["User"] = relationship(back_populates="bookings")
    space: Mapped["ParkingSpace"] = relationship(back_populates="bookings")

    __table_args__ = (
        Index("ix_bookings_space_status", "space_id", "status"),
        # A parking space can only ever have one open (Pending/Active) booking.
        # Enforced by the database so concurrent requests cannot race.
        Index(
            "uq_bookings_open_space",
            "space_id",
            unique=True,
            postgresql_where=text("status IN ('Pending', 'Active')"),
            sqlite_where=text("status IN ('Pending', 'Active')"),
        ),
    )


def status_color(status: BookingStatus | str | None) -> str:
    """Colour a space is displayed with for a given open-booking status."""
    if status is None:
        return AVAILABLE_COLOR
    if not isinstance(status, BookingStatus):
        status = BookingStatus(str(status))
    return STATUS_COLORS.get(status, AVAILABLE_COLOR)


def open_booking_for_space(space: ParkingSpace) -> Booking | None:
    """Return the space's current open booking, preferring an active one.

    Completed and cancelled bookings never hold a space, and one stale
    historical booking can never mask the current state.
    """
    candidate: Booking | None = None
    for booking in space.bookings:
        if booking.status not in OPEN_BOOKING_STATUSES:
            continue
        if booking.status == BookingStatus.ACTIVE:
            return booking
        candidate = booking
    return candidate


def get_space_status(space: ParkingSpace) -> tuple[BookingStatus | None, str]:
    """Return ``(open_status_or_none, color)`` for a parking space.

    Shared by the admin grids, the customer grids and the JSON API so every
    surface derives the same colour from the same persisted booking data.
    """
    booking = open_booking_for_space(space)
    status = booking.status if booking else None
    return status, status_color(status)


def is_space_available(space: ParkingSpace) -> bool:
    """True when the space has no open (Pending/Active) booking."""
    return open_booking_for_space(space) is None


def find_open_booking(
    db: Session, space_id: int, exclude_booking_id: int | None = None
) -> Booking | None:
    """Query the single open booking of a space, if any.

    ``exclude_booking_id`` lets an edit ignore the booking being changed.
    """
    statement = select(Booking).where(
        Booking.space_id == space_id,
        Booking.status.in_(OPEN_BOOKING_STATUSES),
    )
    if exclude_booking_id is not None:
        statement = statement.where(Booking.id != exclude_booking_id)
    return db.scalars(statement.order_by(Booking.id)).first()


def lot_space_count(db: Session, lot_id: int) -> int:
    """Number of parking spaces already registered for a lot."""
    existing = db.scalar(
        select(func.count()).select_from(ParkingSpace).where(
            ParkingSpace.lot_id == lot_id
        )
    )
    return int(existing) if existing is not None else 0


def is_space_available_for_capacity(lot: ParkingLot, db: Session) -> bool:
    """True when adding one more space to lot would not exceed capacity."""
    return lot_space_count(db, lot.id) + 1 <= lot.capacity


def lock_lot(db: Session, lot_id: int) -> ParkingLot | None:
    """Load a lot with a row lock so concurrent space creation serialises."""
    return db.get(ParkingLot, lot_id, with_for_update=True)


def lock_space(db: Session, space_id: int) -> ParkingSpace | None:
    """Load a space with a row lock so concurrent bookings serialise."""
    return db.get(ParkingSpace, space_id, with_for_update=True)
