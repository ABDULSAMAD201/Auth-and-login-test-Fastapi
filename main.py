import hashlib
import hmac
import logging
import os
import secrets
import smtplib
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlencode

import httpx
import uvicorn
from authlib.integrations.starlette_client import OAuth
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

import database
from models import (
    OPEN_BOOKING_STATUSES,
    Booking,
    BookingStatus,
    ParkingLot,
    ParkingSpace,
    User,
    find_open_booking,
    get_space_status,
    is_space_available_for_capacity,
    lock_lot,
    lock_space,
    lot_space_count,
    now_utc,
    open_booking_for_space,
    status_color,
)
from schemas import (
    APIResponse,
    AdminTicketListResponse,
    AdminTicketResponse,
    BookingResponse,
    BookingStatusField,
    ChangePassword,
    ForgotPassword,
    Login,
    ParkingLotSpacesResponse,
    ParkingLotSummary,
    ParkingSpaceResponse,
    Register,
    ResetPassword,
    UserResponse,
)

BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.getenv("APP_ENV", "development").lower()
BOOKING_ROOM_THRESHOLD_MINUTES = int(os.getenv("BOOKING_ROOM_THRESHOLD_MINUTES", "5"))
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
SESSION_MAX_AGE = 60 * 60 * 24 * 30
SESSION_LENGTH = 60 * 60 * 24 * 30
REGULAR_SESSION_LENGTH = 60 * 60 * 8
RESET_TOKEN_LENGTH = 60 * 30
SIGN_IN_MAX_FAILED_ATTEMPTS = 5
SIGN_IN_LOCKOUT_LENGTH = 60 * 30
US_STATES = (
    "Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado",
    "Connecticut", "Delaware", "Florida", "Georgia", "Hawaii", "Idaho",
    "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky", "Louisiana",
    "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
    "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada",
    "New Hampshire", "New Jersey", "New Mexico", "New York",
    "North Carolina", "North Dakota", "Ohio", "Oklahoma", "Oregon",
    "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota",
    "Tennessee", "Texas", "Utah", "Vermont", "Virginia", "Washington",
    "West Virginia", "Wisconsin", "Wyoming", "District of Columbia",
)
logger = logging.getLogger("signin_auth")


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# Passwords are hashed with scrypt. A random salt is generated per password and
# stored alongside the digest, so the stored value carries algorithm, salt and
# hash.
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


# Rehashes the password and compares it with the stored hash using a
# constant-time comparison to avoid leaking information through timing.
def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1
        )
        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------
def create_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def csrf_is_valid(request: Request, form: Mapping[str, object]) -> bool:
    submitted = str(form.get("csrf_token", ""))
    expected = str(request.session.get("csrf_token", ""))
    return bool(expected) and hmac.compare_digest(submitted, expected)


CSRF_MESSAGE = "Your session expired. Please try again."


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def _navigation_user(request: Request):
    """Signed-in user for the shared navigation bar.

    Unlike :func:`signed_in_user` this never clears a session that simply has
    no signed-in identity, so anonymous flows (Google registration, password
    reset) keep their temporary session state.
    """
    if not request.session.get("email"):
        return None
    return signed_in_user(request)


def render(
    request: Request,
    template_name: str,
    context: dict[str, object] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    values = context or {}
    values.setdefault("field_errors", {})
    values.setdefault("form_errors", {})
    # Exposes the signed-in identity to the shared navigation. Resolved before
    # the CSRF token so an expired session cannot invalidate the fresh token.
    values.setdefault("nav_user", _navigation_user(request))
    values["csrf_token"] = create_csrf_token(request)
    values["google_enabled"] = bool(
        os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET")
    )
    values["recaptcha_site_key"] = os.getenv("RECAPTCHA_SITE_KEY", "")
    values["development_mode"] = APP_ENV != "production"
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=values,
        status_code=status_code,
    )


# ---------------------------------------------------------------------------
# Authorization helpers
# ---------------------------------------------------------------------------
def require_admin(user: User) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return user


def require_customer(user: User) -> User:
    if user.role != "customer":
        raise HTTPException(status_code=403, detail="Customer access required.")
    return user


def is_current_user_admin(request: Request) -> bool:
    signed = signed_in_user(request)
    if not signed:
        return False
    return signed.role == "admin"


def _admin_required_redirect(request: Request) -> RedirectResponse | None:
    """Guard for admin HTML endpoints.

    Unauthenticated visitors are redirected to the sign-in page; authenticated
    non-admins get HTTP 403 through :func:`require_admin`.
    """
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_admin(user)
    return None


def _customer_required_redirect(request: Request) -> RedirectResponse | None:
    """Guard for customer HTML endpoints."""
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_customer(user)
    return None


def require_signed_in_user(request: Request) -> User:
    """Signed-in user for handlers that already ran a ``_*_required_redirect``.

    Those guards have already sent anonymous visitors away, so a missing user
    here only happens if the session was invalidated between the two lookups.
    """
    user = signed_in_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return user


def _user_id_for_session(request: Request) -> str:
    """Identifier of the signed-in account (the users table key)."""
    return require_signed_in_user(request).email


def _require_current_user_booking(request: Request, booking: Booking) -> Booking:
    """Customers may only touch their own bookings."""
    user_id = _user_id_for_session(request)
    if booking.user_id != user_id:
        raise HTTPException(status_code=403, detail="You do not own this booking.")
    return booking


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def is_valid_parking_lot_capacity(value: str) -> int:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Capacity is required.")
    try:
        capacity = int(value)
    except ValueError:
        raise ValueError("Capacity must be a whole number.")
    if capacity < 1:
        raise ValueError("Capacity must be a positive number.")
    return capacity


def parse_datetime(value: str) -> datetime:
    """Parse a submitted booking timestamp as UTC.

    Consistent timezone policy: every timestamp stored and compared by the
    application is timezone-aware UTC. Naive input (``datetime-local``) is
    interpreted as UTC.
    """
    if not isinstance(value, str):
        raise ValueError("Invalid booking time format.")
    value = value.strip()
    if not value:
        raise ValueError("Invalid booking time format.")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Invalid booking time format.")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Booking / space presentation helpers
# ---------------------------------------------------------------------------
def space_view(space: ParkingSpace) -> dict[str, object]:
    """Serialisable snapshot of a space and its current open booking.

    The colour comes from the shared :func:`models.get_space_status` helper, so
    the admin grid, the customer grid and the JSON API can never disagree.
    """
    booking = open_booking_for_space(space)
    _, color = get_space_status(space)
    status = booking.status if booking else None
    value = status.value if status else None
    return {
        "id": space.id,
        "name": space.name,
        "notes": space.notes,
        "status": value,
        "color": color,
        "booking_id": booking.id if booking else None,
        "booking_user_id": booking.user_id if booking else None,
        "status_field": {"value": value, "color": color},
    }


def load_lot_spaces(db: Session, lot_id: int) -> list[ParkingSpace]:
    """Spaces of a lot with bookings eagerly loaded (safe after session close)."""
    return list(
        db.scalars(
            select(ParkingSpace)
            .where(ParkingSpace.lot_id == lot_id)
            .options(selectinload(ParkingSpace.bookings))
            .order_by(ParkingSpace.id)
        ).all()
    )


def lot_space_summary(db: Session, lot: ParkingLot) -> ParkingLotSummary:
    total = lot_space_count(db, lot.id)
    available = db.scalar(
        select(func.count())
        .select_from(ParkingSpace)
        .where(
            ParkingSpace.lot_id == lot.id,
            ~ParkingSpace.bookings.any(
                Booking.status.in_(OPEN_BOOKING_STATUSES)
            ),
        )
    )
    available_count = int(available) if available is not None else 0
    return ParkingLotSummary(
        id=lot.id,
        name=lot.name,
        location=lot.location,
        capacity=lot.capacity,
        total_spaces=total,
        available_spaces=max(available_count, 0),
    )


def booking_response(booking: Booking) -> BookingResponse:
    status = BookingStatus(booking.status)
    lot_id = booking.space.lot_id if booking.space else 0
    return BookingResponse(
        id=booking.id,
        space_id=booking.space_id,
        lot_id=lot_id,
        start_time=booking.start_time,
        end_time=booking.end_time,
        status=status.value,
        started_at=booking.started_at,
        ended_at=booking.ended_at,
        status_field=BookingStatusField(
            value=status.value, color=status_color(status)
        ),
    )


def admin_booking_rows(bookings: list[Booking]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for booking in bookings:
        user = booking.user
        space = booking.space
        lot = space.lot if space else None
        status = BookingStatus(booking.status)
        rows.append(
            {
                "id": booking.id,
                "customer_name": (user.full_name if user else None)
                or (user.email if user else "Unknown customer"),
                "customer_email": user.email if user else "",
                "customer_phone": (user.phone if user else "") or "",
                "lot_id": lot.id if lot else None,
                "lot_name": lot.name if lot else "",
                "space_id": space.id if space else None,
                "space_name": space.name if space else "",
                "start_time": booking.start_time,
                "end_time": booking.end_time,
                "started_at": booking.started_at,
                "ended_at": booking.ended_at,
                "status": status.value,
                "color": status_color(status),
                "is_open": status in OPEN_BOOKING_STATUSES,
            }
        )
    return rows


def admin_ticket_rows(bookings: list[Booking]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for booking in bookings:
        user = booking.user
        space = booking.space
        lot = space.lot if space else None
        status = BookingStatus(booking.status)
        rows.append(
            {
                "id": booking.id,
                "customer_name": (user.full_name if user else None)
                or (user.email if user else "Unknown customer"),
                "customer_email": user.email if user else "",
                "lot_id": lot.id if lot else None,
                "lot_name": lot.name if lot else "",
                "space_id": space.id if space else None,
                "space_name": space.name if space else "",
                "status": status.value,
                "status_field": {"value": status.value, "color": status_color(status)},
                "start_time": booking.start_time,
                "end_time": booking.end_time,
                "started_at": booking.started_at,
                "ended_at": booking.ended_at,
            }
        )
    return rows


def space_options(db: Session) -> list[dict[str, object]]:
    """Every space, labelled with its lot, for the admin booking editor."""
    spaces = db.scalars(
        select(ParkingSpace)
        .options(selectinload(ParkingSpace.lot))
        .order_by(ParkingSpace.lot_id, ParkingSpace.id)
    ).all()
    return [
        {
            "id": space.id,
            "lot_id": space.lot_id,
            "label": f"{space.lot.name if space.lot else 'Lot'} · {space.name}",
        }
        for space in spaces
    ]


# ---------------------------------------------------------------------------
# Users / sessions
# ---------------------------------------------------------------------------
def get_user(email: str) -> User | None:
    with database.SessionLocal() as db:
        return db.get(User, email)


def validation_messages(error: ValidationError) -> tuple[dict[str, str], str]:
    field_errors: dict[str, str] = {}
    first_message = "Field is required."
    for item in error.errors():
        location = item["loc"]
        field = str(location[-1]) if location else "form"
        message = str(item.get("ctx", {}).get("error", item["msg"]))
        if item["type"] == "missing":
            message = "Field is required."
        elif message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        if field == "form" and "terms and conditions" in message:
            field = "terms"
        field_errors[field] = message
        if first_message == "Field is required." or field == "terms":
            first_message = message
    return field_errors, first_message


def create_registered_user(db: Session, payload: Register) -> User:
    """Create an account. Public registration always yields a customer.

    The role is assigned here rather than read from the request, so a crafted
    payload can never register an administrator.
    """
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        phone=payload.phone,
        state=payload.state,
        terms_accepted_at=int(time.time()),
        role="customer",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(
    db: Session, email: str, password: str, now: int | None = None
) -> tuple[User | None, str | None, int]:
    current_time = int(time.time()) if now is None else now
    user = db.get(User, email)
    if user and user.locked_until is not None and user.locked_until > current_time:
        return (
            None,
            "Your account has been locked due to multiple unsuccessful sign-in attempts. "
            "Please reset your password.",
            423,
        )
    if not user or not verify_password(password, user.password_hash):
        if user:
            failed_attempts = int(user.failed_attempts or 0)
            if user.locked_until is not None and user.locked_until <= current_time:
                failed_attempts = 0
            failed_attempts += 1
            user.failed_attempts = failed_attempts
            user.locked_until = (
                current_time + SIGN_IN_LOCKOUT_LENGTH
                if failed_attempts >= SIGN_IN_MAX_FAILED_ATTEMPTS
                else None
            )
            db.commit()
        return None, "Incorrect email or password.", 401
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    return user, None, 200


def issue_reset_token(db: Session, email: str) -> str | None:
    user = db.get(User, email)
    if not user:
        return None
    raw_token = secrets.token_urlsafe(32)
    user.reset_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    user.reset_expires_at = int(time.time()) + RESET_TOKEN_LENGTH
    db.commit()
    return raw_token


def reset_user_password(db: Session, payload: ResetPassword) -> bool:
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    user = db.scalar(
        select(User).where(
            User.reset_token_hash == token_hash,
            User.reset_expires_at > int(time.time()),
        )
    )
    if not user:
        return False
    user.password_hash = hash_password(payload.password)
    user.reset_token_hash = None
    user.reset_expires_at = None
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    return True


def change_user_password(db: Session, user: User, payload: ChangePassword) -> bool:
    if not verify_password(payload.current_password, user.password_hash):
        return False
    user.password_hash = hash_password(payload.password)
    user.reset_token_hash = None
    user.reset_expires_at = None
    db.commit()
    return True


def signed_in_user(request: Request) -> User | None:
    email = request.session.get("email")
    expires_at = request.session.get("expires_at", 0)
    if not email or not isinstance(expires_at, int) or expires_at <= int(time.time()):
        request.session.clear()
        return None
    user = get_user(email)
    if not user or request.session.get("sv") != user.session_version:
        request.session.clear()
        return None
    return user


def start_session(request: Request, user: User, remember: bool = False) -> None:
    request.session.clear()
    request.session["email"] = user.email
    request.session["sv"] = user.session_version
    request.session["expires_at"] = int(time.time()) + (
        SESSION_LENGTH if remember else REGULAR_SESSION_LENGTH
    )
    create_csrf_token(request)


def redirect_to_login(message: str = "") -> RedirectResponse:
    suffix = f"?{urlencode({'message': message})}" if message else ""
    return RedirectResponse(f"/login{suffix}", status_code=303)


def landing_page_for(user: User) -> str:
    """Admins land on the admin workspace, customers on their dashboard."""
    return "/admin" if user.role == "admin" else "/dashboard"


# ---------------------------------------------------------------------------
# CAPTCHA / email
# ---------------------------------------------------------------------------
def recaptcha_configured() -> bool:
    return bool(os.getenv("RECAPTCHA_SITE_KEY") and os.getenv("RECAPTCHA_SECRET_KEY"))


async def recaptcha_is_valid(token: str, remote_ip: str | None) -> bool:
    if not recaptcha_configured():
        return APP_ENV != "production"
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={
                    "secret": os.environ["RECAPTCHA_SECRET_KEY"],
                    "response": token,
                    "remoteip": remote_ip or "",
                },
            )
        return response.is_success and bool(response.json().get("success"))
    except (httpx.HTTPError, ValueError):
        logger.exception("reCAPTCHA verification failed")
        return False


async def verify_captcha(token: str, remote_ip: str | None) -> bool:
    result = recaptcha_is_valid(token, remote_ip)
    if hasattr(result, "__await__"):
        return bool(await result)
    return bool(result)


def send_reset_email(email: str, reset_url: str) -> None:
    if not os.getenv("SMTP_HOST"):
        if APP_ENV != "production":
            logger.warning("Development password reset link for %s: %s", email, reset_url)
        else:
            logger.error("Password reset email is not configured")
        return

    message = EmailMessage()
    message["Subject"] = "Reset your Sign-In Portal password"
    message["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", ""))
    message["To"] = email
    message.set_content(
        f"Use this link within 30 minutes to reset your password:\n\n{reset_url}\n"
    )
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "587"))) as smtp:
        smtp.starttls()
        if os.getenv("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        smtp.send_message(message)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(title="Sign-In Portal")


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    del request
    errors = exc.errors()
    if not errors:
        message = "Field is required."
    else:
        error = errors[0]
        if error["type"] == "missing":
            message = "Field is required."
        else:
            message = str(error.get("ctx", {}).get("error", error["msg"]))
            if message.startswith("Value error, "):
                message = message.removeprefix("Value error, ")
    return JSONResponse(status_code=422, content={"detail": message})


app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="signin_session",
    max_age=SESSION_MAX_AGE,
    same_site="lax",
    https_only=APP_ENV == "production",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


oauth = OAuth()
if os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"):
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ---------------------------------------------------------------------------
# Account landing page
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, summary="Show the signed-in account page")
async def home(request: Request):
    user = signed_in_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return render(
        request,
        "account.html",
        {
            "email": user.email,
            "role": user.role,
            "workspace_url": landing_page_for(user),
            "welcome_message": (
                f"Welcome, {user.full_name}!"
                if request.query_params.get("welcome")
                else ""
            ),
        },
    )


# ---------------------------------------------------------------------------
# Admin: dashboard, parking lots, spaces
# ---------------------------------------------------------------------------
@app.get("/admin", response_class=HTMLResponse, summary="Admin-only dashboard")
async def admin_page(request: Request):
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = signed_in_user(request)

    with database.SessionLocal() as db:
        lots = list(db.scalars(select(ParkingLot).order_by(ParkingLot.id)).all())
        lot_summaries = [lot_space_summary(db, lot) for lot in lots]
        total_spaces = int(
            db.scalar(select(func.count()).select_from(ParkingSpace)) or 0
        )
        open_bookings = int(
            db.scalar(
                select(func.count())
                .select_from(Booking)
                .where(Booking.status.in_(OPEN_BOOKING_STATUSES))
            )
            or 0
        )
        recent_bookings = admin_booking_rows(
            list(
                db.scalars(
                    select(Booking)
                    .options(
                        selectinload(Booking.user),
                        selectinload(Booking.space).selectinload(ParkingSpace.lot),
                    )
                    .order_by(Booking.id.desc())
                    .limit(10)
                ).all()
            )
        )

    return render(
        request,
        "admin.html",
        {
            "email": user.email if user else "",
            "full_name": (user.full_name or user.email) if user else "",
            "parking_lots": lot_summaries,
            "recent_bookings": recent_bookings,
            "totals": {
                "lots": len(lot_summaries),
                "spaces": total_spaces,
                "open_bookings": open_bookings,
            },
        },
    )


@app.get(
    "/admin/parking-lots",
    response_class=HTMLResponse,
    summary="Parking lot management",
)
async def parking_lot_page(request: Request):
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    with database.SessionLocal() as db:
        lots = list(db.scalars(select(ParkingLot).order_by(ParkingLot.id)).all())
        lot_summaries = [lot_space_summary(db, lot) for lot in lots]

    return render(
        request,
        "parking_lots.html",
        {
            "parking_lots": lot_summaries,
            "added": request.query_params.get("added"),
        },
    )


# Handlers that can answer with more than one response type (an HTML page, a
# redirect or JSON) are annotated ``-> Response``; each route's
# ``response_class`` still documents the success path.
@app.post(
    "/admin/parking-lots",
    response_class=HTMLResponse,
    summary="Create a parking lot",
)
async def create_parking_lot(request: Request) -> Response:
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    form = await request.form()
    values = {
        "name": str(form.get("name", "")).strip(),
        "location": str(form.get("location", "")).strip(),
        "capacity": str(form.get("capacity", "")).strip(),
    }

    def invalid_page(errors: dict[str, str], status_code: int = 400) -> HTMLResponse:
        with database.SessionLocal() as db:
            lots = list(db.scalars(select(ParkingLot).order_by(ParkingLot.id)).all())
            lot_summaries = [lot_space_summary(db, lot) for lot in lots]
        return render(
            request,
            "parking_lots.html",
            {
                "parking_lots": lot_summaries,
                "form_values": values,
                "form_errors": errors,
            },
            status_code,
        )

    if not csrf_is_valid(request, form):
        return invalid_page({"form": CSRF_MESSAGE}, 403)

    errors: dict[str, str] = {}
    capacity: int | None = None
    try:
        capacity = is_valid_parking_lot_capacity(values["capacity"])
    except ValueError as error:
        errors["capacity"] = str(error)

    if not values["name"]:
        errors["name"] = "Name is required."
    if not values["location"]:
        errors["location"] = "Location is required."

    if errors or capacity is None:
        return invalid_page(errors)

    try:
        with database.SessionLocal.begin() as db:
            db.add(
                ParkingLot(
                    name=values["name"],
                    location=values["location"],
                    capacity=capacity,
                )
            )
    except IntegrityError:
        return invalid_page({"form": "A parking lot with that name already exists."})
    except Exception:
        logger.exception("Unexpected error while creating parking lot")
        return invalid_page(
            {"form": "An unexpected error occurred. Please try again."}, 500
        )

    return RedirectResponse(
        f"/admin/parking-lots?{urlencode({'added': values['name']})}",
        status_code=303,
    )


@app.get(
    "/admin/parking-lots/{lot_id:int}",
    response_class=HTMLResponse,
    summary="View a parking lot and manage its spaces",
)
async def parking_lot_detail_page(request: Request, lot_id: int) -> Response:
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    with database.SessionLocal() as db:
        lot = db.get(ParkingLot, lot_id)
        if not lot:
            return RedirectResponse("/admin/parking-lots", status_code=303)
        spaces = load_lot_spaces(db, lot.id)
        views = [space_view(space) for space in spaces]
        space_total = lot_space_count(db, lot.id)
        lot_payload = {
            "id": lot.id,
            "name": lot.name,
            "location": lot.location,
            "capacity": lot.capacity,
        }

    return render(
        request,
        "parking_lot_detail.html",
        {
            "lot": lot_payload,
            "space_views": views,
            "space_total": space_total,
            "added": request.query_params.get("added"),
            # One-shot confirmation set when a space was just created.
            "space_notice": request.session.pop("space_notice", None),
        },
    )


@app.post(
    "/admin/parking-lots/{lot_id:int}/spaces",
    response_class=HTMLResponse,
    summary="Add a parking space to a lot",
)
async def create_parking_space(request: Request, lot_id: int) -> Response:
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    form = await request.form()
    values = {
        "name": str(form.get("name", "")).strip(),
        "notes": str(form.get("notes", "")).strip(),
    }

    def detail_page(errors: dict[str, str], status_code: int = 400) -> Response:
        with database.SessionLocal() as db:
            lot = db.get(ParkingLot, lot_id)
            if not lot:
                return RedirectResponse("/admin/parking-lots", status_code=303)
            spaces = load_lot_spaces(db, lot.id)
            views = [space_view(space) for space in spaces]
            payload = {
                "id": lot.id,
                "name": lot.name,
                "location": lot.location,
                "capacity": lot.capacity,
            }
        return render(
            request,
            "parking_lot_detail.html",
            {
                "lot": payload,
                "space_views": views,
                "form_values": values,
                "form_errors": errors,
            },
            status_code,
        )

    if not csrf_is_valid(request, form):
        return detail_page({"form": CSRF_MESSAGE}, 403)

    if not values["name"]:
        return detail_page({"name": "Space name is required."})

    duplicate_exists = False
    try:
        with database.SessionLocal.begin() as db:
            # Lock the lot so concurrent submissions cannot both pass the
            # capacity check and overshoot the limit.
            lot = lock_lot(db, lot_id)
            if not lot:
                return RedirectResponse("/admin/parking-lots", status_code=303)

            # A space name must be unique inside its own lot. The duplicate is
            # reported before the capacity limit because it is the more
            # specific problem.
            duplicate_exists = (
                db.scalar(
                    select(ParkingSpace).where(
                        ParkingSpace.lot_id == lot.id,
                        ParkingSpace.name == values["name"],
                    )
                )
                is not None
            )
            if not duplicate_exists:
                if not is_space_available_for_capacity(lot, db):
                    raise ValueError(
                        f"Total spaces exceed the defined parking lot capacity of {lot.capacity}"
                    )

                db.add(
                    ParkingSpace(
                        lot_id=lot.id,
                        name=values["name"],
                        notes=values["notes"] or None,
                    )
                )
    except ValueError as error:
        return detail_page({"form": str(error)})
    except IntegrityError:
        return detail_page(
            {"name": "A space with that name already exists in this lot."}
        )
    except Exception:
        logger.exception("Unexpected error while adding parking space")
        return detail_page(
            {"form": "An unexpected error occurred. Please try again."}, 500
        )

    if duplicate_exists:
        return detail_page(
            {"name": "A space with that name already exists in this lot."}
        )

    request.session["space_notice"] = f"Added {values['name']}."
    return RedirectResponse(f"/admin/parking-lots/{lot_id}", status_code=303)


# ---------------------------------------------------------------------------
# Admin: booking management
# ---------------------------------------------------------------------------
ADMIN_BOOKING_MESSAGES = {
    "updated": ("success", "Booking updated."),
    "cancelled": ("success", "Booking cancelled and the space was released."),
    "conflict": ("error", "That space already has an open booking."),
    "invalid": ("error", "That change is not allowed for this booking."),
    "invalid_time": ("error", "End time must be after start time."),
    "invalid_format": ("error", "Enter valid start and end times."),
    "space_not_found": ("error", "Select an existing parking space."),
    "not_found": ("error", "That booking no longer exists."),
}


def _booking_flash(params) -> dict[str, str]:
    for key, (kind, message) in ADMIN_BOOKING_MESSAGES.items():
        if params.get(key):
            return {"kind": kind, "message": message}
    return {}


def _admin_bookings_redirect(*, lot_id: str = "", **flags: str) -> RedirectResponse:
    params = {key: value for key, value in flags.items() if value}
    if lot_id:
        params["lot_id"] = lot_id
    query = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(f"/admin/bookings{query}", status_code=303)


@app.get(
    "/admin/bookings",
    response_class=HTMLResponse,
    summary="Admin-only booking management",
)
async def admin_bookings_page(request: Request):
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    lot_id_filter = request.query_params.get("lot_id", "").strip()
    selected_lot: int | None = None
    if lot_id_filter.isdigit():
        selected_lot = int(lot_id_filter)

    with database.SessionLocal() as db:
        lots = list(db.scalars(select(ParkingLot).order_by(ParkingLot.id)).all())
        statement = (
            select(Booking)
            .options(
                selectinload(Booking.user),
                selectinload(Booking.space).selectinload(ParkingSpace.lot),
            )
            .order_by(Booking.id.desc())
        )
        if selected_lot is not None:
            statement = statement.join(
                ParkingSpace, Booking.space_id == ParkingSpace.id
            ).where(ParkingSpace.lot_id == selected_lot)
        bookings = list(db.scalars(statement).all())
        rows = admin_booking_rows(bookings)
        options = space_options(db)

    return render(
        request,
        "admin_bookings.html",
        {
            "booking_rows": rows,
            "lots": [{"id": lot.id, "name": lot.name} for lot in lots],
            "selected_lot": selected_lot,
            "space_options": options,
            "flash": _booking_flash(request.query_params),
        },
    )


@app.post(
    "/admin/bookings/{booking_id:int}/cancel",
    response_class=HTMLResponse,
    summary="Cancel a booking as an administrator",
)
async def admin_cancel_booking(request: Request, booking_id: int) -> Response:
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    form = await request.form()
    lot_id = str(form.get("lot_id", "")).strip()
    if not csrf_is_valid(request, form):
        return _admin_bookings_redirect(lot_id=lot_id, invalid="1")

    try:
        with database.SessionLocal.begin() as db:
            booking = db.get(Booking, booking_id)
            if not booking:
                return _admin_bookings_redirect(lot_id=lot_id, not_found="1")
            # Completed and cancelled bookings cannot transition again.
            if BookingStatus(booking.status) not in OPEN_BOOKING_STATUSES:
                return _admin_bookings_redirect(lot_id=lot_id, invalid="1")
            booking.status = BookingStatus.CANCELLED
    except Exception:
        logger.exception("Unexpected error while cancelling booking as admin")
        return _admin_bookings_redirect(lot_id=lot_id, invalid="1")

    return _admin_bookings_redirect(lot_id=lot_id, cancelled="1")


@app.post(
    "/admin/bookings/{booking_id:int}/update",
    response_class=HTMLResponse,
    summary="Modify a booking's space or times as an administrator",
)
async def admin_update_booking(request: Request, booking_id: int) -> Response:
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    form = await request.form()
    lot_filter = str(form.get("lot_id", "")).strip()
    space_field = str(form.get("space_id", "")).strip()
    if not csrf_is_valid(request, form):
        return _admin_bookings_redirect(lot_id=lot_filter, invalid="1")

    if not space_field.isdigit():
        return _admin_bookings_redirect(lot_id=lot_filter, space_not_found="1")

    try:
        start_time = parse_datetime(str(form.get("start_time", "")))
        end_time = parse_datetime(str(form.get("end_time", "")))
    except ValueError:
        return _admin_bookings_redirect(lot_id=lot_filter, invalid_format="1")

    if end_time <= start_time:
        return _admin_bookings_redirect(lot_id=lot_filter, invalid_time="1")

    target_space_id = int(space_field)

    try:
        with database.SessionLocal.begin() as db:
            booking = db.get(Booking, booking_id)
            if not booking:
                return _admin_bookings_redirect(lot_id=lot_filter, not_found="1")
            if BookingStatus(booking.status) not in OPEN_BOOKING_STATUSES:
                return _admin_bookings_redirect(lot_id=lot_filter, invalid="1")

            # Lock the destination space so two concurrent edits cannot both
            # see it as free.
            space = lock_space(db, target_space_id)
            if not space:
                return _admin_bookings_redirect(
                    lot_id=lot_filter, space_not_found="1"
                )

            conflict = find_open_booking(db, space.id, exclude_booking_id=booking.id)
            if conflict is not None:
                return _admin_bookings_redirect(lot_id=lot_filter, conflict="1")

            booking.space_id = space.id
            booking.start_time = start_time
            booking.end_time = end_time
    except IntegrityError:
        return _admin_bookings_redirect(lot_id=lot_filter, conflict="1")
    except Exception:
        logger.exception("Unexpected error while updating booking as admin")
        return _admin_bookings_redirect(lot_id=lot_filter, invalid="1")

    return _admin_bookings_redirect(lot_id=lot_filter, updated="1")


def load_open_bookings(db: Session) -> list[Booking]:
    """Pending and Active bookings, oldest first."""
    return list(
        db.scalars(
            select(Booking)
            .where(Booking.status.in_(OPEN_BOOKING_STATUSES))
            .options(
                selectinload(Booking.user),
                selectinload(Booking.space).selectinload(ParkingSpace.lot),
            )
            .order_by(Booking.id)
        ).all()
    )


@app.get(
    "/admin/tickets",
    response_class=HTMLResponse,
    summary="Admin-only view of pending and active tickets",
)
async def admin_tickets_page(request: Request):
    redirect_or_none = _admin_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    with database.SessionLocal() as db:
        rows = admin_ticket_rows(load_open_bookings(db))

    return render(request, "admin_tickets.html", {"ticket_rows": rows})


# ---------------------------------------------------------------------------
# Customer: dashboard, lots, bookings
# ---------------------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse, summary="Customer dashboard")
async def dashboard_page(request: Request):
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = require_signed_in_user(request)

    with database.SessionLocal() as db:
        lots = list(db.scalars(select(ParkingLot).order_by(ParkingLot.id)).all())
        lot_summaries = [lot_space_summary(db, lot) for lot in lots]
        my_bookings = list(
            db.scalars(
                select(Booking)
                .where(Booking.user_id == user.email)
                .options(selectinload(Booking.space).selectinload(ParkingSpace.lot))
                .order_by(Booking.id.desc())
            ).all()
        )

    return render(
        request,
        "dashboard.html",
        {
            "email": user.email,
            "lots": lot_summaries,
            "open_tickets": admin_booking_rows(
                [
                    booking
                    for booking in my_bookings
                    if BookingStatus(booking.status) in OPEN_BOOKING_STATUSES
                ]
            ),
            "welcome_message": (
                f"Welcome, {user.full_name}!"
                if request.query_params.get("welcome")
                else ""
            ),
        },
    )


@app.get(
    "/dashboard/lots/{lot_id:int}",
    response_class=HTMLResponse,
    summary="Customer view of a parking lot's spaces",
)
async def customer_lot_page(request: Request, lot_id: int) -> Response:
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = require_signed_in_user(request)

    with database.SessionLocal() as db:
        lot = db.get(ParkingLot, lot_id)
        if not lot:
            return RedirectResponse("/dashboard", status_code=303)
        spaces = load_lot_spaces(db, lot.id)
        views = [space_view(space) for space in spaces]
        summary = lot_space_summary(db, lot)

    return render(
        request,
        "lot_spaces.html",
        {"lot": summary, "space_views": views, "user_id": user.email},
    )


@app.get(
    "/dashboard/bookings",
    response_class=HTMLResponse,
    summary="Customer bookings and tickets",
)
async def customer_bookings_page(request: Request) -> Response:
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = require_signed_in_user(request)

    with database.SessionLocal() as db:
        bookings = list(
            db.scalars(
                select(Booking)
                .where(Booking.user_id == user.email)
                .options(selectinload(Booking.space).selectinload(ParkingSpace.lot))
                .order_by(Booking.id.desc())
            ).all()
        )
        rows = admin_booking_rows(bookings)

    return render(
        request,
        "customer_bookings.html",
        {"booking_rows": rows, "flash": _customer_flash(request)},
    )


# ---------------------------------------------------------------------------
# Customer: booking actions
# ---------------------------------------------------------------------------
BOOKING_REDIRECT_TARGETS = {"space", "bookings"}

CUSTOMER_BOOKING_MESSAGES = {
    "created": ("success", "Ticket generated. The space is now reserved for you."),
    "started": ("success", "Ticket started. You are now using this space."),
    "ended": ("success", "Ticket ended and the booking is now completed."),
    "cancelled": ("success", "Booking cancelled. This space is available again."),
    "conflict": ("error", "This space already has an open booking."),
    "invalid": ("error", "That action is not allowed for this booking."),
    "forbidden": ("error", "You do not have permission to do that."),
    "not_found": ("error", "That booking was not found."),
    "expired": ("error", CSRF_MESSAGE),
}


def _customer_flash(request: Request) -> dict[str, str]:
    """Translate the action flags on the query string into a user message."""
    for key, (kind, text) in CUSTOMER_BOOKING_MESSAGES.items():
        if request.query_params.get(key):
            return {"kind": kind, "message": text}
    return {}


def _booking_action_redirect(
    lot_id: int, space_id: int, flag: str, target: str
) -> RedirectResponse:
    """Send the customer back where they came from (allow-listed targets)."""
    if target == "bookings":
        return RedirectResponse(
            f"/dashboard/bookings?{urlencode({flag: '1'})}", status_code=303
        )
    return RedirectResponse(
        f"/dashboard/lots/{lot_id}/spaces/{space_id}?{urlencode({flag: '1'})}",
        status_code=303,
    )


def _booking_action_context(
    db: Session, lot_id: int, space_id: int
) -> dict[str, object]:
    lot = db.get(ParkingLot, lot_id)
    space = db.get(ParkingSpace, space_id)
    if not lot or not space or space.lot_id != lot.id:
        return {}
    return {
        "lot": lot_space_summary(db, lot),
        "space": space_view(space),
        "bookings": [],
        "user_id": None,
        "flash": {},
    }


@app.get(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}",
    response_class=HTMLResponse,
    summary="Customer space detail and ticket actions",
)
async def customer_space_page(
    request: Request, lot_id: int, space_id: int
) -> Response:
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = require_signed_in_user(request)

    with database.SessionLocal() as db:
        lot = db.get(ParkingLot, lot_id)
        if not lot:
            return RedirectResponse("/dashboard", status_code=303)
        space = db.get(ParkingSpace, space_id)
        if not space or space.lot_id != lot.id:
            return RedirectResponse("/dashboard", status_code=303)
        bookings = list(
            db.scalars(
                select(Booking)
                .where(Booking.space_id == space.id)
                .order_by(Booking.id)
            ).all()
        )
        view = space_view(space)
        lot_summary = lot_space_summary(db, lot)

    # Customers only ever see their own bookings for the space; other people's
    # booking rows are never exposed.
    my_bookings = [booking for booking in bookings if booking.user_id == user.email]
    active_booking = next(
        (
            booking
            for booking in my_bookings
            if BookingStatus(booking.status) == BookingStatus.ACTIVE
        ),
        None,
    )

    return render(
        request,
        "customer_space.html",
        {
            "lot": lot_summary,
            "space": view,
            "my_bookings": my_bookings,
            "active_booking": active_booking,
            "user_id": user.email,
            "flash": _customer_flash(request),
        },
    )


@app.get(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}/new",
    response_class=HTMLResponse,
    summary="Prepare a booking request for an available space",
)
async def customer_space_new_page(
    request: Request, lot_id: int, space_id: int
) -> Response:
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    with database.SessionLocal() as db:
        lot = db.get(ParkingLot, lot_id)
        if not lot:
            return RedirectResponse("/dashboard", status_code=303)
        space = db.get(ParkingSpace, space_id)
        if not space or space.lot_id != lot.id:
            return RedirectResponse("/dashboard", status_code=303)
        view = space_view(space)
        if view["status"] is not None:
            return RedirectResponse(
                f"/dashboard/lots/{lot_id}/spaces/{space_id}", status_code=303
            )
        lot_summary = lot_space_summary(db, lot)

    return render(
        request,
        "customer_space_new.html",
        {"lot": lot_summary, "space": view, "form_values": {}, "form_errors": {}},
    )


@app.post(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}/book",
    response_class=HTMLResponse,
    summary="Create a pending booking for a space",
)
async def create_booking(request: Request, lot_id: int, space_id: int) -> Response:
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none
    user = require_signed_in_user(request)

    form = await request.form()
    wants_json = (
        request.headers.get("x-requested-with", "") == "XMLHttpRequest"
        or request.headers.get("accept", "").startswith("application/json")
    )
    values = {
        "start_time": str(form.get("start_time", "")),
        "end_time": str(form.get("end_time", "")),
    }

    def validation_errors() -> dict[str, str]:
        errors: dict[str, str] = {}
        try:
            start = parse_datetime(values["start_time"])
        except ValueError as error:
            errors["start_time"] = str(error)
            start = None
        try:
            end = parse_datetime(values["end_time"])
        except ValueError as error:
            errors["end_time"] = str(error)
            end = None
        if start and end and end <= start:
            errors["end_time"] = "End time must be after start time."
        return errors

    if not csrf_is_valid(request, form):
        if wants_json:
            return JSONResponse(status_code=403, content={"detail": CSRF_MESSAGE})
        return _booking_action_redirect(lot_id, space_id, "expired", "space")

    errors = validation_errors()
    if errors:
        if wants_json:
            return JSONResponse(status_code=400, content={"detail": errors})
        with database.SessionLocal() as db:
            context = _booking_action_context(db, lot_id, space_id)
        return render(
            request,
            "customer_space_new.html",
            {**context, "form_values": values, "form_errors": errors},
            400,
        )

    start_time = parse_datetime(values["start_time"])
    end_time = parse_datetime(values["end_time"])

    try:
        with database.SessionLocal.begin() as db:
            # Lock the space: a space can only ever hold one open booking.
            space = lock_space(db, space_id)
            if not space or space.lot_id != lot_id:
                if wants_json:
                    return JSONResponse(
                        status_code=404, content={"detail": "Space not found."}
                    )
                return _booking_action_redirect(
                    lot_id, space_id, "not_found", "space"
                )

            if find_open_booking(db, space.id) is not None:
                if wants_json:
                    return JSONResponse(
                        status_code=409,
                        content={
                            "detail": "This space already has an open booking."
                        },
                    )
                return _booking_action_redirect(
                    lot_id, space_id, "conflict", "space"
                )

            booking = Booking(
                # Ownership comes from the session, never from the request.
                user_id=user.email,
                space_id=space.id,
                start_time=start_time,
                end_time=end_time,
                status=BookingStatus.PENDING,
            )
            db.add(booking)
            db.flush()
            payload = booking_response(booking)

        if wants_json:
            return JSONResponse(
                status_code=201,
                content={
                    "detail": "Ticket generated. The space is now reserved for you.",
                    "booking": payload.model_dump(mode="json"),
                },
            )
        return _booking_action_redirect(lot_id, space_id, "created", "space")
    except IntegrityError:
        if wants_json:
            return JSONResponse(
                status_code=409,
                content={"detail": "This space already has an open booking."},
            )
        return _booking_action_redirect(lot_id, space_id, "conflict", "space")
    except Exception:
        logger.exception("Unexpected error while creating booking")
        if wants_json:
            return JSONResponse(
                status_code=500,
                content={"detail": "An unexpected error occurred. Please try again."},
            )
        return _booking_action_redirect(lot_id, space_id, "invalid", "space")


async def _booking_transition(
    request: Request,
    lot_id: int,
    space_id: int,
    *,
    expected: BookingStatus,
    new_status: BookingStatus,
    flag: str,
    stamp: str | None,
) -> Response:
    """Shared implementation for the start/end/cancel ticket actions."""
    redirect_or_none = _customer_required_redirect(request)
    if redirect_or_none is not None:
        return redirect_or_none

    form = await request.form()
    target = str(form.get("redirect_to", "space"))
    if target not in BOOKING_REDIRECT_TARGETS:
        target = "space"

    if not csrf_is_valid(request, form):
        return _booking_action_redirect(lot_id, space_id, "expired", target)

    booking_field = str(form.get("booking_id", "")).strip()
    if not booking_field.isdigit():
        return _booking_action_redirect(lot_id, space_id, "invalid", target)
    booking_id = int(booking_field)

    redirect_lot_id = lot_id
    redirect_space_id = space_id
    try:
        with database.SessionLocal.begin() as db:
            booking = db.get(Booking, booking_id)
            if not booking or booking.space_id != space_id:
                return _booking_action_redirect(
                    lot_id, space_id, "not_found", target
                )
            _require_current_user_booking(request, booking)
            redirect_lot_id = booking.space.lot_id if booking.space else lot_id
            if BookingStatus(booking.status) != expected:
                return _booking_action_redirect(lot_id, space_id, "invalid", target)
            booking.status = new_status
            if stamp == "started_at":
                booking.started_at = now_utc()
            elif stamp == "ended_at":
                booking.ended_at = now_utc()
    except HTTPException as error:
        if error.status_code == 403:
            return _booking_action_redirect(lot_id, space_id, "forbidden", target)
        raise
    except Exception:
        logger.exception("Unexpected error while updating booking")
        return _booking_action_redirect(lot_id, space_id, "invalid", target)

    return _booking_action_redirect(
        redirect_lot_id, redirect_space_id, flag, target
    )


@app.post(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}/start",
    response_class=HTMLResponse,
    summary="Start a pending ticket",
)
async def start_booking(request: Request, lot_id: int, space_id: int) -> Response:
    return await _booking_transition(
        request,
        lot_id,
        space_id,
        expected=BookingStatus.PENDING,
        new_status=BookingStatus.ACTIVE,
        flag="started",
        stamp="started_at",
    )


@app.post(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}/end",
    response_class=HTMLResponse,
    summary="End an active ticket",
)
async def end_booking(request: Request, lot_id: int, space_id: int) -> Response:
    return await _booking_transition(
        request,
        lot_id,
        space_id,
        expected=BookingStatus.ACTIVE,
        new_status=BookingStatus.COMPLETED,
        flag="ended",
        stamp="ended_at",
    )


@app.post(
    "/dashboard/lots/{lot_id:int}/spaces/{space_id:int}/cancel",
    response_class=HTMLResponse,
    summary="Cancel a pending booking",
)
async def cancel_booking(request: Request, lot_id: int, space_id: int) -> Response:
    return await _booking_transition(
        request,
        lot_id,
        space_id,
        expected=BookingStatus.PENDING,
        new_status=BookingStatus.CANCELLED,
        flag="cancelled",
        stamp=None,
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------
@app.get(
    "/api/lots/{lot_id:int}/spaces",
    response_model=ParkingLotSpacesResponse,
    summary="Current status of every space in a parking lot",
)
def api_lot_spaces(
    lot_id: int, request: Request, db: Session = Depends(database.get_db)
):
    """Live space statuses, calculated from persisted bookings.

    Any signed-in user may read customer-facing lot data; anonymous callers
    receive HTTP 401.
    """
    if not signed_in_user(request):
        return JSONResponse(status_code=401, content={"detail": "Not signed in."})

    lot = db.get(ParkingLot, lot_id)
    if not lot:
        return JSONResponse(
            status_code=404, content={"detail": "Parking lot not found."}
        )

    spaces = load_lot_spaces(db, lot.id)
    return ParkingLotSpacesResponse(
        lot=lot_space_summary(db, lot),
        spaces=[
            ParkingSpaceResponse.model_validate(space_view(space))
            for space in spaces
        ],
    )


@app.get(
    "/api/admin/tickets",
    response_model=AdminTicketListResponse,
    summary="Open tickets (Pending and Active bookings)",
)
def api_admin_tickets(request: Request, db: Session = Depends(database.get_db)):
    user = signed_in_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not signed in."})
    require_admin(user)
    return AdminTicketListResponse(
        tickets=[
            AdminTicketResponse.model_validate(row)
            for row in admin_ticket_rows(load_open_bookings(db))
        ]
    )


@app.get(
    "/api/me",
    response_model=UserResponse,
    summary="Get the signed-in user's public profile",
)
def api_current_user(request: Request, db: Session = Depends(database.get_db)):
    signed_user = signed_in_user(request)
    if not signed_user:
        return JSONResponse(status_code=401, content={"detail": "Not signed in."})
    user = db.get(User, signed_user.email)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not signed in."})
    return user


@app.post(
    "/api/register",
    response_model=APIResponse,
    status_code=201,
    summary="Create an account",
)
def api_register(
    payload: Register, request: Request, db: Session = Depends(database.get_db)
):
    google_registration = request.session.get("google_registration", {})
    if google_registration.get("email"):
        payload = payload.model_copy(
            update={
                "email": str(google_registration["email"]).strip().lower(),
                "full_name": payload.full_name
                or str(google_registration.get("name", "")).strip(),
            }
        )
    if payload.state not in US_STATES:
        return JSONResponse(
            status_code=422, content={"detail": "Select a valid state."}
        )
    try:
        user = create_registered_user(db, payload)
    except IntegrityError:
        db.rollback()
        return JSONResponse(
            status_code=409,
            content={"detail": "An account with this email already exists."},
        )
    start_session(request, user)
    return APIResponse(
        message=f"Welcome, {user.full_name}!",
        user=UserResponse.model_validate(user),
        redirect_to="/dashboard",
    )


@app.post(
    "/api/login",
    response_model=APIResponse,
    summary="Sign in and start a session",
)
async def api_login(
    payload: Login, request: Request, db: Session = Depends(database.get_db)
):
    if not payload.captcha:
        return JSONResponse(
            status_code=400,
            content={"detail": "Please complete the reCAPTCHA."},
        )

    verified = await verify_captcha(
        payload.captcha, request.client.host if request.client else None
    )
    if not verified:
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Verification failed. Please complete the CAPTCHA to proceed."
            },
        )
    user, error, status_code = authenticate_user(db, payload.email, payload.password)
    if error:
        return JSONResponse(status_code=status_code, content={"detail": error})
    assert user is not None
    start_session(request, user, remember=payload.remember)
    return APIResponse(
        message="Sign in successful.",
        user=UserResponse.model_validate(user),
        redirect_to=landing_page_for(user),
    )


@app.post(
    "/api/forgot-password",
    response_model=APIResponse,
    summary="Request a password reset link",
)
def api_forgot_password(
    payload: ForgotPassword,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(database.get_db),
):
    token = issue_reset_token(db, payload.email)
    if token:
        public_base_url = os.getenv("PUBLIC_BASE_URL")
        if public_base_url or APP_ENV != "production":
            base_url = (public_base_url or str(request.base_url)).rstrip("/")
            background_tasks.add_task(
                send_reset_email,
                payload.email,
                f"{base_url}/reset-password?token={token}",
            )
        else:
            logger.error(
                "PUBLIC_BASE_URL must be configured to send password reset links"
            )
    return APIResponse(
        message="If an account matches that email, password reset instructions are on their way."
    )


@app.post(
    "/api/reset-password",
    response_model=APIResponse,
    summary="Reset a password with a token",
)
def api_reset_password(payload: ResetPassword, db: Session = Depends(database.get_db)):
    if not reset_user_password(db, payload):
        return JSONResponse(
            status_code=400,
            content={"detail": "This reset link is invalid or has expired."},
        )
    return APIResponse(message="Password updated. Sign in with your new password.")


@app.post(
    "/api/change-password",
    response_model=APIResponse,
    summary="Change the signed-in user's password",
)
def api_change_password(
    payload: ChangePassword,
    request: Request,
    db: Session = Depends(database.get_db),
):
    signed_user = signed_in_user(request)
    if not signed_user:
        return JSONResponse(
            status_code=401,
            content={"detail": "Please sign in to change your password."},
        )
    user = db.get(User, signed_user.email)
    if user is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "Please sign in to change your password."},
        )
    if not change_user_password(db, user, payload):
        return JSONResponse(
            status_code=400,
            content={"detail": "Your current password is incorrect."},
        )
    request.session.clear()
    return APIResponse(message="Password updated. Sign in again with your new password.")


# ---------------------------------------------------------------------------
# Registration / sign-in pages
# ---------------------------------------------------------------------------
@app.get("/register", response_class=HTMLResponse, summary="Show the registration form")
async def register_page(request: Request, message: str = ""):
    if request.session.get("email") and signed_in_user(request):
        return RedirectResponse("/", status_code=303)
    google_registration = request.session.get("google_registration", {})
    return render(
        request,
        "register.html",
        {
            "full_name": google_registration.get("name", ""),
            "email": google_registration.get("email", ""),
            "google_registration": bool(google_registration.get("email")),
            "states": US_STATES,
            "message": message,
        },
    )


@app.post(
    "/register", response_class=HTMLResponse, summary="Submit the registration form"
)
async def register(request: Request):
    form = await request.form()
    google_registration = request.session.get("google_registration", {})
    google_email = str(google_registration.get("email", "")).strip().lower()
    values = {
        "full_name": str(form.get("full_name", "")).strip()
        or str(google_registration.get("name", "")).strip(),
        "email": google_email or str(form.get("email", "")).strip(),
        "password": str(form.get("password", "")),
        "phone": str(form.get("phone", "")).strip(),
        "state": str(form.get("state", "")).strip(),
        "terms": form.get("terms") == "on",
    }
    full_name = values["full_name"]
    email = values["email"]
    phone = values["phone"]
    state = values["state"]

    if not csrf_is_valid(request, form):
        return render(
            request,
            "register.html",
            {
                "error": CSRF_MESSAGE,
                "full_name": full_name,
                "email": email,
                "phone": phone,
                "state": state,
                "google_registration": bool(google_email),
                "states": US_STATES,
            },
            403,
        )

    field_errors: dict[str, str] = {}
    payload: Register | None = None
    try:
        payload = Register.model_validate(values)
        if payload.state not in US_STATES:
            raise ValueError("Select a valid state.")
    except ValidationError as error:
        field_errors, _ = validation_messages(error)
    except ValueError as error:
        field_errors = {"state": str(error)}

    context: dict[str, object] = {
        "field_errors": field_errors,
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "state": state,
        "terms_checked": values["terms"],
        "google_registration": bool(google_email),
        "states": US_STATES,
    }
    if field_errors or payload is None:
        return render(request, "register.html", context, 400)

    try:
        with database.SessionLocal() as db:
            user = create_registered_user(db, payload)
    except IntegrityError:
        return render(
            request,
            "register.html",
            {**context, "error": "An account with this email already exists."},
            409,
        )
    except Exception:
        logger.exception("Unexpected error while registering account")
        return render(
            request,
            "register.html",
            {
                **context,
                "error": "An unexpected error occurred. Please try again later.",
            },
            500,
        )

    start_session(request, user)
    return RedirectResponse("/?welcome=1", status_code=303)


@app.get("/login", response_class=HTMLResponse, summary="Show the sign-in form")
async def login_page(request: Request, message: str = ""):
    if signed_in_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"message": message})


@app.post("/login", response_class=HTMLResponse, summary="Submit the sign-in form")
async def login(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "login.html", {"error": CSRF_MESSAGE}, 403)

    try:
        payload = Login.model_validate(
            {
                "email": str(form.get("email", "")),
                "password": str(form.get("password", "")),
                "captcha": str(form.get("g-recaptcha-response", "")),
                "remember": form.get("remember") == "on",
            }
        )
    except ValidationError as validation_error:
        field_errors, _ = validation_messages(validation_error)
        email = str(form.get("email", "")).strip().lower()
        return render(
            request,
            "login.html",
            {"field_errors": field_errors, "email_value": email},
            400,
        )

    email = payload.email
    if not payload.captcha:
        return render(
            request,
            "login.html",
            {"error": "Please complete the reCAPTCHA.", "email_value": email},
            400,
        )

    try:
        now = int(time.time())
        user = get_user(email)
        if user and user.locked_until is not None and user.locked_until > now:
            return render(
                request,
                "login.html",
                {
                    "error": (
                        "Your account has been locked due to multiple unsuccessful "
                        "sign-in attempts. Please reset your password."
                    ),
                    "email_value": email,
                },
                423,
            )

        verified = await verify_captcha(
            payload.captcha, request.client.host if request.client else None
        )
        if not verified:
            return render(
                request,
                "login.html",
                {
                    "error": "Verification failed. Please complete the CAPTCHA to proceed.",
                    "email_value": email,
                },
                401,
            )

        with database.SessionLocal() as db:
            user, error, status_code = authenticate_user(
                db, email, payload.password, now
            )
        if error:
            return render(
                request,
                "login.html",
                {"error": error, "email_value": email},
                status_code,
            )
        assert user is not None
        start_session(request, user, remember=payload.remember)
        return RedirectResponse(landing_page_for(user), status_code=303)
    except Exception:
        logger.exception("Unexpected error while signing in")
        return render(
            request,
            "login.html",
            {
                "error": "An unexpected error occurred. Please try again later.",
                "email_value": email,
            },
            500,
        )


@app.post("/logout", summary="Sign out of the current session")
async def logout(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return redirect_to_login(CSRF_MESSAGE)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------------------------------------------------------------------------
# Password recovery / change
# ---------------------------------------------------------------------------
@app.get(
    "/forgot-password",
    response_class=HTMLResponse,
    summary="Show password reset request form",
)
async def forgot_password_page(request: Request):
    return render(request, "forgot_password.html")


@app.post(
    "/forgot-password",
    response_class=HTMLResponse,
    summary="Request a password reset link",
)
async def forgot_password(request: Request, background_tasks: BackgroundTasks):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "forgot_password.html", {"error": CSRF_MESSAGE}, 403)

    try:
        payload = ForgotPassword.model_validate({"email": str(form.get("email", ""))})
    except ValidationError as error:
        _, message = validation_messages(error)
        return render(request, "forgot_password.html", {"error": message}, 400)

    with database.SessionLocal() as db:
        raw_token = issue_reset_token(db, payload.email)
    if raw_token:
        public_base_url = os.getenv("PUBLIC_BASE_URL")
        if public_base_url or APP_ENV != "production":
            base_url = (public_base_url or str(request.base_url)).rstrip("/")
            reset_url = f"{base_url}/reset-password?token={raw_token}"
            background_tasks.add_task(send_reset_email, payload.email, reset_url)
        else:
            logger.error(
                "PUBLIC_BASE_URL must be configured to send password reset links"
            )

    return render(
        request,
        "forgot_password.html",
        {
            "success": "If an account matches that email, password reset instructions are on their way."
        },
    )


@app.get(
    "/reset-password",
    response_class=HTMLResponse,
    summary="Show the password reset form",
)
async def reset_password_page(request: Request, token: str = ""):
    return render(request, "reset_password.html", {"token": token})


@app.post(
    "/reset-password", response_class=HTMLResponse, summary="Submit a password reset"
)
async def reset_password(request: Request):
    form = await request.form()
    token = str(form.get("token", ""))
    if not csrf_is_valid(request, form):
        return render(
            request,
            "reset_password.html",
            {"token": token, "error": CSRF_MESSAGE},
            403,
        )
    try:
        payload = ResetPassword.model_validate(
            {
                "token": token,
                "password": str(form.get("password", "")),
                "confirm_password": str(form.get("confirm_password", "")),
            }
        )
    except ValidationError as error:
        _, message = validation_messages(error)
        return render(
            request, "reset_password.html", {"token": token, "error": message}, 400
        )

    with database.SessionLocal() as db:
        reset = reset_user_password(db, payload)
    if not reset:
        return render(
            request,
            "reset_password.html",
            {"token": "", "error": "This reset link is invalid or has expired."},
            400,
        )
    request.session.clear()
    return redirect_to_login("Password updated. Sign in with your new password.")


@app.get(
    "/change-password",
    response_class=HTMLResponse,
    summary="Show password change form",
)
async def change_password_page(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    return render(request, "change_password.html")


@app.post(
    "/change-password",
    response_class=HTMLResponse,
    summary="Change the signed-in user's password",
)
async def change_password(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "change_password.html", {"error": CSRF_MESSAGE}, 403)

    try:
        payload = ChangePassword.model_validate(
            {
                "current_password": str(form.get("current_password", "")),
                "password": str(form.get("password", "")),
                "confirm_password": str(form.get("confirm_password", "")),
            }
        )
    except ValidationError as error:
        _, message = validation_messages(error)
        return render(request, "change_password.html", {"error": message}, 400)

    with database.SessionLocal() as db:
        db_user = db.get(User, user.email)
        if not db_user:
            return redirect_to_login("Please sign in to change your password.")
        changed = change_user_password(db, db_user, payload)
    if not changed:
        return render(
            request,
            "change_password.html",
            {"error": "Your current password is incorrect."},
            400,
        )
    request.session.clear()
    return redirect_to_login("Password updated. Sign in again with your new password.")


# ---------------------------------------------------------------------------
# Google sign-in
# ---------------------------------------------------------------------------
@app.get("/auth/google", summary="Start Google sign-in")
async def google_login(request: Request, flow: str = "login"):
    flow = "signup" if flow == "signup" else "login"
    destination = "/register" if flow == "signup" else "/login"
    if not (os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET")):
        query = urlencode({"message": "Google sign-in is not configured yet."})
        return RedirectResponse(f"{destination}?{query}", status_code=303)
    request.session["google_flow"] = flow
    return await oauth.google.authorize_redirect(
        request, str(request.url_for("google_callback"))
    )


@app.get(
    "/auth/google/callback", name="google_callback", summary="Complete Google sign-in"
)
async def google_callback(request: Request):
    flow = request.session.get("google_flow", "login")
    try:
        token = await oauth.google.authorize_access_token(request)
        profile = token.get("userinfo") or await oauth.google.userinfo(token=token)
    except Exception:
        logger.exception("Google OAuth callback failed")
        destination = "/register" if flow == "signup" else "/login"
        query = urlencode({"message": "Google sign-in could not be completed."})
        return RedirectResponse(f"{destination}?{query}", status_code=303)

    email = str(profile.get("email", "")).strip().lower()
    if not email or not profile.get("email_verified"):
        destination = "/register" if flow == "signup" else "/login"
        query = urlencode({"message": "Google could not verify your email address."})
        return RedirectResponse(f"{destination}?{query}", status_code=303)
    user = get_user(email)
    if user:
        start_session(request, user)
        return RedirectResponse("/", status_code=303)

    request.session.clear()
    request.session["google_registration"] = {
        "email": email,
        "name": str(profile.get("name", "")).strip(),
    }
    create_csrf_token(request)
    return RedirectResponse("/register", status_code=303)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
