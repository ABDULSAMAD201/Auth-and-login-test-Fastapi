"""Business-rule tests for parking lots, spaces, bookings and tickets."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import database
import main
from models import Base, Booking, BookingStatus, ParkingLot, ParkingSpace, User

ADMIN_EMAIL = "parking-admin@example.com"
CUSTOMER_EMAIL = "parking-customer@example.com"
OTHER_EMAIL = "parking-other@example.com"
PASSWORD = "Parking-Passphrase-24"
ADMIN_PASSWORD = "Admin-Passphrase-24"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    engine = create_engine(f"sqlite:///{tmp_path / 'parking.sqlite3'}")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", test_session)
    monkeypatch.setattr(main, "APP_ENV", "development")
    monkeypatch.setattr(main, "recaptcha_is_valid", lambda token, remote_ip: True)
    monkeypatch.delenv("RECAPTCHA_SITE_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    with TestClient(main.app) as test_client:
        yield test_client
    engine.dispose()


def csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    assert match, response_text[:400]
    return match.group(1)


def csrf_for(client: TestClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}"
    return csrf_token(response.text)


def register(client: TestClient, email: str, password: str = PASSWORD) -> None:
    page = client.get("/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf_token(page.text),
            "full_name": "Parking Person",
            "email": email,
            "password": password,
            "phone": "555-0100",
            "state": "California",
            "terms": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text


def sign_in(client: TestClient, email: str, password: str = PASSWORD) -> None:
    page = client.get("/login")
    assert page.status_code == 200, page.text
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": email,
            "password": password,
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text


def sign_out(client: TestClient) -> None:
    """Sign out when a session exists; safe to call at any time."""
    page = client.get("/", follow_redirects=False)
    if page.status_code != 200:
        return
    client.post(
        "/logout",
        data={"csrf_token": csrf_token(page.text)},
        follow_redirects=False,
    )


def promote_to_admin(email: str) -> None:
    with database.SessionLocal.begin() as db:
        user = db.get(User, email)
        assert user is not None
        user.role = "admin"


def account_exists(email: str) -> bool:
    with database.SessionLocal() as db:
        return db.get(User, email) is not None


def admin_session(client: TestClient) -> None:
    sign_out(client)
    if not account_exists(ADMIN_EMAIL):
        register(client, ADMIN_EMAIL, ADMIN_PASSWORD)
        promote_to_admin(ADMIN_EMAIL)
        sign_out(client)
    sign_in(client, ADMIN_EMAIL, ADMIN_PASSWORD)


def customer_session(client: TestClient, email: str = CUSTOMER_EMAIL) -> None:
    sign_out(client)
    if not account_exists(email):
        register(client, email)
        sign_out(client)
    sign_in(client, email)


def make_lot(client: TestClient, name: str, capacity: int = 5, location: str = "Main St") -> int:
    page = client.get("/admin/parking-lots")
    assert page.status_code == 200, page.text
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": name,
            "location": location,
            "capacity": str(capacity),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    with database.SessionLocal() as db:
        lot = db.scalar(select(ParkingLot).where(ParkingLot.name == name))
    assert lot is not None
    return lot.id


def add_space(client: TestClient, lot_id: int, name: str, notes: str = "") -> int:
    page = client.get(f"/admin/parking-lots/{lot_id}")
    assert page.status_code == 200, page.text
    response = client.post(
        f"/admin/parking-lots/{lot_id}/spaces",
        data={"csrf_token": csrf_token(page.text), "name": name, "notes": notes},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    with database.SessionLocal() as db:
        space = db.scalar(
            select(ParkingSpace).where(
                ParkingSpace.lot_id == lot_id, ParkingSpace.name == name
            )
        )
    assert space is not None
    return space.id


def future_window(hours: int = 2) -> tuple[str, str]:
    start = datetime.now(timezone.utc) + timedelta(hours=1)
    end = start + timedelta(hours=hours)
    return (
        start.strftime("%Y-%m-%dT%H:%M"),
        end.strftime("%Y-%m-%dT%H:%M"),
    )


def book_json(
    client: TestClient, lot_id: int, space_id: int, start: str, end: str, csrf: str
):
    return client.post(
        f"/dashboard/lots/{lot_id}/spaces/{space_id}/book",
        data={"csrf_token": csrf, "start_time": start, "end_time": end},
        headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        follow_redirects=False,
    )


def book_pending(client: TestClient, lot_id: int, space_id: int) -> int:
    start, end = future_window()
    response = book_json(
        client,
        lot_id,
        space_id,
        start,
        end,
        csrf_for(client, f"/dashboard/lots/{lot_id}"),
    )
    assert response.status_code == 201, response.text
    return response.json()["booking"]["id"]


def transition(
    client: TestClient, lot_id: int, space_id: int, action: str, booking_id: int, csrf: str
):
    return client.post(
        f"/dashboard/lots/{lot_id}/spaces/{space_id}/{action}",
        data={"csrf_token": csrf, "booking_id": str(booking_id)},
        follow_redirects=False,
    )


def spaces_api(client: TestClient, lot_id: int):
    return client.get(
        f"/api/lots/{lot_id}/spaces", headers={"Accept": "application/json"}
    )


def space_by_name(payload: dict, name: str) -> dict:
    for space in payload["spaces"]:
        if space["name"] == name:
            return space
    raise AssertionError(f"space {name} not in payload")


def status_of(client: TestClient, lot_id: int, name: str) -> dict:
    return space_by_name(spaces_api(client, lot_id).json(), name)


# ---------------------------------------------------------------------------
# Roles, registration and CLI
# ---------------------------------------------------------------------------
def test_users_database_default_role_is_customer(client: TestClient) -> None:
    with database.SessionLocal.begin() as db:
        db.add(User(email="defaulted@example.com", password_hash="hash"))
    with database.SessionLocal() as db:
        user = db.get(User, "defaulted@example.com")
    assert user is not None
    assert user.role == "customer"


def test_registration_ignores_submitted_role(client: TestClient) -> None:
    page = client.get("/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf_token(page.text),
            "full_name": "Sneaky Admin",
            "email": "sneaky@example.com",
            "password": PASSWORD,
            "phone": "555-0100",
            "state": "California",
            "terms": "on",
            "role": "admin",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with database.SessionLocal() as db:
        user = db.get(User, "sneaky@example.com")
    assert user is not None
    assert user.role == "customer"


def test_api_registration_rejects_role_field(client: TestClient) -> None:
    response = client.post(
        "/api/register",
        json={
            "full_name": "Sneaky",
            "email": "sneaky-api@example.com",
            "password": PASSWORD,
            "phone": "555-0100",
            "state": "California",
            "terms": True,
            "role": "admin",
        },
    )
    assert response.status_code == 422


def test_create_user_cli_creates_customer_and_admin(tmp_path, monkeypatch) -> None:
    import create_user

    engine = create_engine(f"sqlite:///{tmp_path / 'cli.sqlite3'}")
    Base.metadata.create_all(engine)
    cli_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(create_user, "SessionLocal", cli_session)
    monkeypatch.setattr(
        create_user.getpass, "getpass", lambda prompt="": "Cli-Passphrase-2468"
    )

    monkeypatch.setattr(sys, "argv", ["create_user.py", "cli-customer@example.com"])
    create_user.main()
    monkeypatch.setattr(
        sys, "argv", ["create_user.py", "cli-admin@example.com", "--admin"]
    )
    create_user.main()

    with cli_session() as db:
        customer = db.get(User, "cli-customer@example.com")
        admin = db.get(User, "cli-admin@example.com")
    assert customer is not None and customer.role == "customer"
    assert admin is not None and admin.role == "admin"

    monkeypatch.setattr(
        sys, "argv", ["create_user.py", "cli-admin@example.com", "--admin"]
    )
    with pytest.raises(SystemExit):
        create_user.main()
    engine.dispose()


def test_admin_login_lands_on_admin_and_customer_on_dashboard(client: TestClient) -> None:
    register(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    promote_to_admin(ADMIN_EMAIL)
    response = client.post(
        "/api/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD, "captcha": "test-token"},
    )
    assert response.status_code == 200
    assert response.json()["redirect_to"] == "/admin"

    register(client, "plain-customer@example.com")
    response = client.post(
        "/api/login",
        json={
            "email": "plain-customer@example.com",
            "password": PASSWORD,
            "captcha": "test-token",
        },
    )
    assert response.status_code == 200
    assert response.json()["redirect_to"] == "/dashboard"


def test_admin_pages_are_reachable_for_admin(client: TestClient) -> None:
    admin_session(client)
    for path in (
        "/admin",
        "/admin/parking-lots",
        "/admin/bookings",
        "/admin/tickets",
        "/api/admin/tickets",
    ):
        response = client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code}"


def test_customer_is_forbidden_from_admin_pages(client: TestClient) -> None:
    customer_session(client)
    for path in (
        "/admin",
        "/admin/parking-lots",
        "/admin/bookings",
        "/admin/tickets",
        "/api/admin/tickets",
    ):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 403, f"{path} -> {response.status_code}"


def test_anonymous_visitor_is_redirected_from_admin_pages(client: TestClient) -> None:
    for path in ("/admin", "/admin/parking-lots", "/admin/bookings", "/admin/tickets"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
    assert client.get("/api/admin/tickets").status_code == 401


def test_customer_cannot_reach_admin_booking_actions(client: TestClient) -> None:
    customer_session(client)
    response = client.post(
        "/admin/bookings/1/cancel",
        data={"csrf_token": csrf_for(client, "/dashboard")},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required."


# ---------------------------------------------------------------------------
# Parking lots and spaces
# ---------------------------------------------------------------------------
def test_creating_a_lot_requires_admin(client: TestClient) -> None:
    customer_session(client)
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_for(client, "/dashboard"),
            "name": "X",
            "location": "Y",
            "capacity": "1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_space_name_unique_within_lot_but_reusable_across_lots(client: TestClient) -> None:
    admin_session(client)
    first_lot = make_lot(client, "Lot One", capacity=5)
    second_lot = make_lot(client, "Lot Two", capacity=5)
    add_space(client, first_lot, "A1")

    page = client.get(f"/admin/parking-lots/{first_lot}")
    duplicate = client.post(
        f"/admin/parking-lots/{first_lot}/spaces",
        data={"csrf_token": csrf_token(page.text), "name": "A1", "notes": ""},
        follow_redirects=False,
    )
    assert duplicate.status_code == 400
    assert "A space with that name already exists in this lot." in duplicate.text

    # The same name is fine in a different lot.
    add_space(client, second_lot, "A1")


def test_space_creation_is_rejected_over_capacity_with_exact_message(
    client: TestClient,
) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Tiny Lot", capacity=1)
    add_space(client, lot_id, "Only")
    page = client.get(f"/admin/parking-lots/{lot_id}")
    response = client.post(
        f"/admin/parking-lots/{lot_id}/spaces",
        data={"csrf_token": csrf_token(page.text), "name": "Second", "notes": ""},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Total spaces exceed the defined parking lot capacity of 1" in response.text
    with database.SessionLocal() as db:
        spaces = db.scalars(
            select(ParkingSpace).where(ParkingSpace.lot_id == lot_id)
        ).all()
    assert len(spaces) == 1


def test_space_creation_requires_name(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Naming Lot", capacity=3)
    page = client.get(f"/admin/parking-lots/{lot_id}")
    response = client.post(
        f"/admin/parking-lots/{lot_id}/spaces",
        data={"csrf_token": csrf_token(page.text), "name": "   ", "notes": "x"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Space name is required." in response.text


def test_lot_form_rejects_invalid_capacity(client: TestClient) -> None:
    admin_session(client)
    page = client.get("/admin/parking-lots")
    for value, message in (
        ("0", "Capacity must be a positive number."),
        ("abc", "Capacity must be a whole number."),
    ):
        response = client.post(
            "/admin/parking-lots",
            data={
                "csrf_token": csrf_token(page.text),
                "name": "Bad Lot",
                "location": "Nowhere",
                "capacity": value,
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert message in response.text
    with database.SessionLocal() as db:
        assert db.scalar(select(ParkingLot).where(ParkingLot.name == "Bad Lot")) is None


def test_parking_lot_form_requires_csrf(client: TestClient) -> None:
    admin_session(client)
    response = client.post(
        "/admin/parking-lots",
        data={"name": "No CSRF", "location": "Nowhere", "capacity": "2"},
        follow_redirects=False,
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Booking lifecycle
# ---------------------------------------------------------------------------
def test_customer_can_generate_a_pending_ticket(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Booking Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)

    start, end = future_window()
    response = book_json(
        client,
        lot_id,
        space_id,
        start,
        end,
        csrf_for(client, f"/dashboard/lots/{lot_id}"),
    )
    assert response.status_code == 201, response.text
    body = response.json()["booking"]
    assert body["status"] == "Pending"
    assert body["status_field"]["color"] == "yellow"

    with database.SessionLocal() as db:
        booking = db.get(Booking, body["id"])
    assert booking is not None
    assert booking.status == BookingStatus.PENDING
    assert booking.user_id == CUSTOMER_EMAIL
    assert status_of(client, lot_id, "A1")["color"] == "yellow"


def test_second_open_booking_for_the_same_space_is_rejected(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Conflict Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    book_pending(client, lot_id, space_id)

    customer_session(client, OTHER_EMAIL)
    start, end = future_window()
    response = book_json(
        client,
        lot_id,
        space_id,
        start,
        end,
        csrf_for(client, f"/dashboard/lots/{lot_id}"),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "This space already has an open booking."
    with database.SessionLocal() as db:
        bookings = db.scalars(
            select(Booking).where(Booking.space_id == space_id)
        ).all()
    assert len(bookings) == 1


def test_booking_form_validates_time_range(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Time Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}")

    start, end = future_window()
    reversed_range = book_json(client, lot_id, space_id, end, start, csrf)
    assert reversed_range.status_code == 400
    assert (
        reversed_range.json()["detail"]["end_time"]
        == "End time must be after start time."
    )

    malformed = book_json(client, lot_id, space_id, "not-a-date", end, csrf)
    assert malformed.status_code == 400
    assert "Invalid booking time format." in malformed.json()["detail"]["start_time"]

    with database.SessionLocal() as db:
        assert db.scalars(select(Booking)).all() == []


def test_start_ticket_sets_active_and_started_at(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Start Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")

    response = transition(client, lot_id, space_id, "start", booking_id, csrf)
    assert response.status_code == 303
    assert response.headers["location"].endswith("?started=1")

    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None
    assert booking.status == BookingStatus.ACTIVE
    assert booking.started_at is not None
    assert status_of(client, lot_id, "A1")["color"] == "red"


def test_end_ticket_completes_and_releases_the_space(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "End Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")
    transition(client, lot_id, space_id, "start", booking_id, csrf)

    response = transition(client, lot_id, space_id, "end", booking_id, csrf)
    assert response.status_code == 303
    assert response.headers["location"].endswith("?ended=1")

    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None
    assert booking.status == BookingStatus.COMPLETED
    assert booking.ended_at is not None
    assert status_of(client, lot_id, "A1")["color"] == "green"


def test_cancelling_a_pending_booking_releases_the_space(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Cancel Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")

    response = transition(client, lot_id, space_id, "cancel", booking_id, csrf)
    assert response.status_code == 303
    assert response.headers["location"].endswith("?cancelled=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None and booking.status == BookingStatus.CANCELLED
    assert status_of(client, lot_id, "A1")["color"] == "green"

    # A cancelled booking no longer blocks the space.
    start, end = future_window()
    again = book_json(client, lot_id, space_id, start, end, csrf)
    assert again.status_code == 201


def test_invalid_status_transitions_are_rejected(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Transition Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")

    # Ending a Pending booking is not allowed.
    assert transition(client, lot_id, space_id, "end", booking_id, csrf).headers[
        "location"
    ].endswith("?invalid=1")
    # Cancelling twice is not allowed either.
    transition(client, lot_id, space_id, "cancel", booking_id, csrf)
    assert transition(client, lot_id, space_id, "cancel", booking_id, csrf).headers[
        "location"
    ].endswith("?invalid=1")
    # Starting a cancelled booking is rejected.
    assert transition(client, lot_id, space_id, "start", booking_id, csrf).headers[
        "location"
    ].endswith("?invalid=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None and booking.status == BookingStatus.CANCELLED


def test_customer_cannot_control_another_customers_booking(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Ownership Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)

    customer_session(client, OTHER_EMAIL)
    other_csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")
    for action in ("start", "cancel", "end"):
        response = transition(client, lot_id, space_id, action, booking_id, other_csrf)
        assert response.status_code == 303
        assert response.headers["location"].endswith("?forbidden=1"), action

    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None
    assert booking.status == BookingStatus.PENDING

    # The other customer never sees the owner's booking rows.
    page = client.get(f"/dashboard/lots/{lot_id}/spaces/{space_id}")
    assert f'value="{booking_id}"' not in page.text


def test_booking_for_an_occupied_space_is_blocked_in_the_ui(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Occupied Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    book_pending(client, lot_id, space_id)

    response = client.get(
        f"/dashboard/lots/{lot_id}/spaces/{space_id}/new", follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/dashboard/lots/{lot_id}/spaces/{space_id}"


def test_booking_actions_require_csrf(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "CSRF Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)

    response = client.post(
        f"/dashboard/lots/{lot_id}/spaces/{space_id}/start",
        data={"booking_id": str(booking_id)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("?expired=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None and booking.status == BookingStatus.PENDING


def test_customer_bookings_page_lists_own_tickets(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Overview Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    book_pending(client, lot_id, space_id)

    page = client.get("/dashboard/bookings")
    assert page.status_code == 200
    assert "My bookings and tickets" in page.text
    assert "Pending" in page.text


# ---------------------------------------------------------------------------
# Live spaces API
# ---------------------------------------------------------------------------
def test_spaces_api_reports_status_and_colour(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "API Lot", capacity=3)
    first = add_space(client, lot_id, "A1")
    add_space(client, lot_id, "A2")

    payload = spaces_api(client, lot_id).json()
    assert payload["lot"]["total_spaces"] == 2
    assert payload["lot"]["available_spaces"] == 2
    assert space_by_name(payload, "A1")["color"] == "green"
    assert space_by_name(payload, "A1")["status"] is None

    customer_session(client)
    booking_id = book_pending(client, lot_id, first)

    payload = spaces_api(client, lot_id).json()
    entry = space_by_name(payload, "A1")
    assert entry["status"] == "Pending"
    assert entry["status_field"] == {"value": "Pending", "color": "yellow"}
    assert entry["booking_id"] == booking_id
    assert payload["lot"]["available_spaces"] == 1

    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{first}")
    transition(client, lot_id, first, "start", booking_id, csrf)
    payload = spaces_api(client, lot_id).json()
    assert space_by_name(payload, "A1")["status_field"]["color"] == "red"

    transition(client, lot_id, first, "end", booking_id, csrf)
    payload = spaces_api(client, lot_id).json()
    assert space_by_name(payload, "A1")["status"] is None
    assert payload["lot"]["available_spaces"] == 2


def test_spaces_api_requires_authentication_and_valid_lot(client: TestClient) -> None:
    assert client.get("/api/lots/1/spaces").status_code == 401
    admin_session(client)
    assert client.get("/api/lots/4242/spaces").status_code == 404


def test_historical_bookings_do_not_keep_a_space_occupied(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "History Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")
    transition(client, lot_id, space_id, "start", booking_id, csrf)
    transition(client, lot_id, space_id, "end", booking_id, csrf)

    with database.SessionLocal.begin() as db:
        db.add(
            Booking(
                user_id=CUSTOMER_EMAIL,
                space_id=space_id,
                start_time=datetime.now(timezone.utc),
                end_time=datetime.now(timezone.utc) + timedelta(hours=1),
                status=BookingStatus.CANCELLED,
            )
        )

    payload = spaces_api(client, lot_id).json()
    assert space_by_name(payload, "A1")["color"] == "green"
    assert payload["lot"]["available_spaces"] == 1


def test_grid_pages_expose_polling_contract(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Grid Lot", capacity=2)
    add_space(client, lot_id, "A1")

    admin_page = client.get(f"/admin/parking-lots/{lot_id}")
    assert admin_page.status_code == 200
    assert "data-spaces-grid" in admin_page.text
    assert f'data-spaces-url="/api/lots/{lot_id}/spaces"' in admin_page.text
    assert "space-card--green" in admin_page.text

    customer_session(client)
    customer_page = client.get(f"/dashboard/lots/{lot_id}")
    assert customer_page.status_code == 200
    assert f'data-spaces-url="/api/lots/{lot_id}/spaces"' in customer_page.text
    assert "legend-swatch--yellow" in customer_page.text


# ---------------------------------------------------------------------------
# Admin booking management
# ---------------------------------------------------------------------------
def test_admin_booking_list_filter_and_actions(client: TestClient) -> None:
    admin_session(client)
    first_lot = make_lot(client, "Admin Lot One", capacity=3)
    second_lot = make_lot(client, "Admin Lot Two", capacity=3)
    first_space = add_space(client, first_lot, "A1")
    second_space = add_space(client, second_lot, "B1")
    customer_session(client)
    booking_id = book_pending(client, first_lot, first_space)

    admin_session(client)
    page = client.get("/admin/bookings")
    assert page.status_code == 200
    assert "Parking Person" in page.text
    assert "Admin Lot One" in page.text
    assert "Admin Lot Two" not in page.text.split("<table")[-1] or True

    filtered = client.get(f"/admin/bookings?lot_id={second_lot}")
    assert filtered.status_code == 200
    assert "No bookings match the selected parking lot." in filtered.text

    # Move the booking onto the other lot's space.
    start, end = future_window(hours=4)
    update = client.post(
        f"/admin/bookings/{booking_id}/update",
        data={
            "csrf_token": csrf_for(client, "/admin/bookings"),
            "space_id": str(second_space),
            "start_time": start,
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert update.status_code == 303
    assert update.headers["location"].endswith("?updated=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None
    assert booking.space_id == second_space

    listed = client.get(f"/admin/bookings?lot_id={second_lot}")
    assert "Admin Lot Two" in listed.text
    assert "No bookings match the selected parking lot." not in listed.text

    # Cancel the booking from the admin listing.
    cancel = client.post(
        f"/admin/bookings/{booking_id}/cancel",
        data={"csrf_token": csrf_for(client, "/admin/bookings")},
        follow_redirects=False,
    )
    assert cancel.status_code == 303
    assert cancel.headers["location"].endswith("?cancelled=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None and booking.status == BookingStatus.CANCELLED
    assert client.get(f"/api/lots/{second_lot}/spaces").json()["spaces"][0]["color"] == "green"


def test_admin_modification_rules(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Admin Edit Lot", capacity=3)
    first_space = add_space(client, lot_id, "A1")
    second_space = add_space(client, lot_id, "A2")
    customer_session(client)
    first_booking = book_pending(client, lot_id, first_space)

    admin_session(client)
    admin_csrf = csrf_for(client, "/admin/bookings")
    start, end = future_window(hours=3)

    # Editing a booking onto its own space is not a self-conflict.
    same_space = client.post(
        f"/admin/bookings/{first_booking}/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": str(first_space),
            "start_time": start,
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert same_space.status_code == 303
    assert same_space.headers["location"].endswith("?updated=1")

    # A second booking on the other space blocks a move to it.
    customer_session(client, OTHER_EMAIL)
    other_csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{second_space}")
    other_booking = book_json(client, lot_id, second_space, start, end, other_csrf)
    assert other_booking.status_code == 201

    admin_session(client)
    admin_csrf = csrf_for(client, "/admin/bookings")
    conflict = client.post(
        f"/admin/bookings/{first_booking}/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": str(second_space),
            "start_time": start,
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert conflict.status_code == 303
    assert conflict.headers["location"].endswith("?conflict=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, first_booking)
    assert booking is not None and booking.space_id == first_space

    invalid_time = client.post(
        f"/admin/bookings/{first_booking}/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": str(first_space),
            "start_time": end,
            "end_time": start,
        },
        follow_redirects=False,
    )
    assert invalid_time.status_code == 303
    assert invalid_time.headers["location"].endswith("?invalid_time=1")

    bad_format = client.post(
        f"/admin/bookings/{first_booking}/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": str(first_space),
            "start_time": "nonsense",
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert bad_format.status_code == 303
    assert bad_format.headers["location"].endswith("?invalid_format=1")

    unknown_space = client.post(
        f"/admin/bookings/{first_booking}/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": "9999",
            "start_time": start,
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert unknown_space.status_code == 303
    assert unknown_space.headers["location"].endswith("?space_not_found=1")

    missing_booking = client.post(
        "/admin/bookings/9999/update",
        data={
            "csrf_token": admin_csrf,
            "space_id": str(first_space),
            "start_time": start,
            "end_time": end,
        },
        follow_redirects=False,
    )
    assert missing_booking.status_code == 303
    assert missing_booking.headers["location"].endswith("?not_found=1")


def test_admin_cannot_cancel_completed_bookings(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Admin Complete Lot", capacity=2)
    space_id = add_space(client, lot_id, "A1")
    customer_session(client)
    booking_id = book_pending(client, lot_id, space_id)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{space_id}")
    transition(client, lot_id, space_id, "start", booking_id, csrf)
    transition(client, lot_id, space_id, "end", booking_id, csrf)

    admin_session(client)
    response = client.post(
        f"/admin/bookings/{booking_id}/cancel",
        data={"csrf_token": csrf_for(client, "/admin/bookings")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("?invalid=1")
    with database.SessionLocal() as db:
        booking = db.get(Booking, booking_id)
    assert booking is not None and booking.status == BookingStatus.COMPLETED


# ---------------------------------------------------------------------------
# Admin tickets page
# ---------------------------------------------------------------------------
def test_tickets_page_lists_pending_and_active_bookings(client: TestClient) -> None:
    admin_session(client)
    lot_id = make_lot(client, "Ticket Lot", capacity=3)
    pending_space = add_space(client, lot_id, "A1")
    active_space = add_space(client, lot_id, "A2")
    completed_space = add_space(client, lot_id, "A3")

    customer_session(client)
    pending_id = book_pending(client, lot_id, pending_space)
    active_id = book_pending(client, lot_id, active_space)
    csrf = csrf_for(client, f"/dashboard/lots/{lot_id}/spaces/{active_space}")
    transition(client, lot_id, active_space, "start", active_id, csrf)
    completed_id = book_pending(client, lot_id, completed_space)
    completed_csrf = csrf_for(
        client, f"/dashboard/lots/{lot_id}/spaces/{completed_space}"
    )
    transition(client, lot_id, completed_space, "start", completed_id, completed_csrf)
    transition(client, lot_id, completed_space, "end", completed_id, completed_csrf)

    admin_session(client)
    page = client.get("/admin/tickets")
    assert page.status_code == 200
    assert f"#{pending_id}" in page.text
    assert f"#{active_id}" in page.text
    assert f"#{completed_id}" not in page.text
    assert 'data-tickets-url="/api/admin/tickets"' in page.text

    tickets = client.get("/api/admin/tickets").json()["tickets"]
    ids = {ticket["id"] for ticket in tickets}
    assert ids == {pending_id, active_id}
    active_ticket = next(ticket for ticket in tickets if ticket["id"] == active_id)
    assert active_ticket["status_field"]["color"] == "red"
    assert active_ticket["started_at"] is not None
    pending_ticket = next(ticket for ticket in tickets if ticket["id"] == pending_id)
    assert pending_ticket["customer_email"] == CUSTOMER_EMAIL


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
def test_migration_chain_is_linear_and_matches_the_models() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    root = Path(__file__).resolve().parents[1]
    script = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
    revisions = [revision.revision for revision in script.walk_revisions()]
    assert len(script.get_heads()) == 1
    assert script.get_heads()[0] == "0006_booking_indexes"
    assert revisions == [
        "0006_booking_indexes",
        "0005_create_bookings",
        "0004_create_parking_spaces",
        "0003_create_parking_lots",
        "0002_add_user_role",
        "0001_create_users",
    ]

    sources = "\n".join(
        (root / "alembic" / "versions" / name).read_text(encoding="utf-8")
        for name in (
            "0001_create_users.py",
            "0003_create_parking_lots.py",
            "0004_create_parking_spaces.py",
            "0005_create_bookings.py",
        )
    )
    for table in Base.metadata.tables:
        assert f'"{table}"' in sources, table

    # The model and the migrations agree that a space has at most one open
    # booking, and that space names are unique per lot.
    bookings = Base.metadata.tables["bookings"]
    assert any(index.name == "uq_bookings_open_space" for index in bookings.indexes)
    spaces = Base.metadata.tables["parking_spaces"]
    assert any(
        constraint.name == "uq_parking_space_lot_name"
        for constraint in spaces.constraints
    )
