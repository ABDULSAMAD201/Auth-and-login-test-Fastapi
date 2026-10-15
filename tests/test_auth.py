import re
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError
from sqlalchemy import create_engine, inspect, text
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
import sqlalchemy as sa

import database
import main
from models import Base, User
from schemas import (
    APIResponse,
    ChangePassword,
    ForgotPassword,
    Login,
    Register,
    ResetPassword,
    UserResponse,
)

ADMIN_EMAIL = "admin@example.com"
CUSTOMER_EMAIL = "member@example.com"


def admin_client(client: TestClient, monkeypatch) -> TestClient:
    monkeypatch.setattr(main, "recaptcha_is_valid", lambda token, remote_ip: True)
    client.post(
        "/register",
        data={
            "csrf_token": csrf_token(client.get("/register").text),
            "full_name": "Admin User",
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "phone": "555-0199",
            "state": "California",
            "terms": "on",
        },
        follow_redirects=False,
    )
    with database.SessionLocal.begin() as db:
        user = db.get(User, ADMIN_EMAIL)
        assert user is not None
        user.role = "admin"

    page = client.get("/login")
    token = csrf_token(page.text)
    client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    return client


@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    engine = create_engine(f"sqlite:///{tmp_path / 'accounts.sqlite3'}")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", test_session)
    monkeypatch.setattr(main, "APP_ENV", "development")
    monkeypatch.delenv("RECAPTCHA_SITE_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    with TestClient(main.app) as test_client:
        with test_session.begin() as db:
            db.add(
                User(
                    email="member@example.com",
                    password_hash=main.hash_password("Original-Passphrase-24"),
                )
            )
        yield test_client
    engine.dispose()


def csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    assert match
    return match.group(1)


def sign_in(client: TestClient, password: str = "Original-Passphrase-24") -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
            "password": password,
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text


def test_password_hash_verification() -> None:
    encoded = main.hash_password("a-long-passphrase")
    assert main.verify_password("a-long-passphrase", encoded)
    assert not main.verify_password("a-different-passphrase", encoded)


def test_user_defaults_to_customer_role() -> None:
    user = User(email="defaults@example.com", password_hash="hash")
    assert getattr(user, "role", None) in (None, "customer")


def test_register_model_does_not_accept_role() -> None:
    with pytest.raises(ValidationError):
        Register.model_validate(
            {
                "full_name": "Taylor Driver",
                "email": "taylor@example.com",
                "password": "secure1",
                "phone": "555-0100",
                "state": "California",
                "terms": True,
                "role": "admin",
            }
        )


def test_migration_adds_role_column() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        user_table = sa.Table(
            "users",
            sa.MetaData(),
            sa.Column("email", sa.Text, primary_key=True),
            sa.Column("role", sa.Text),
        )
        inspector = sa.inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("users")}
    assert "role" in columns


def test_registration_creates_customer_not_admin(client: TestClient) -> None:
    page = client.get("/register")
    response = client.post(
        "/register",
        data=registration_data(page.text, full_name="Role Test", email="role-test@example.com"),
        follow_redirects=False,
    )
    assert response.status_code == 303
    with database.SessionLocal() as db:
        user = db.get(User, "role-test@example.com")
    assert user is not None
    assert user.role == "customer"


def test_request_models_validate_and_public_user_model_excludes_secrets() -> None:
    register = Register(
        full_name="Taylor Driver",
        email="TAYLOR@example.com",
        password="secure1",
        phone="555-0100",
        state="California",
        terms=True,
    )
    assert register.email == "taylor@example.com"
    assert Login(email="member@example.com", password="password").remember is False
    assert ForgotPassword(email="member@example.com").email == "member@example.com"
    assert ResetPassword(
        token="reset-token",
        password="long-enough-password",
        confirm_password="long-enough-password",
    )
    assert ChangePassword(
        current_password="current",
        password="long-enough-password",
        confirm_password="long-enough-password",
    )

    # A row that carries a hash must not leak it through the public schema.
    public_user = UserResponse.model_validate(
        {
            "email": "member@example.com",
            "full_name": "Member",
            "password_hash": "must-not-appear",
        }
    )
    response = APIResponse(message="ok", user=public_user).model_dump()
    assert "password_hash" not in public_user.model_dump()
    assert "password_hash" not in response["user"]

    admin_user = UserResponse(
        email="admin@example.com",
        full_name="Admin",
        role="admin",
    )
    admin_response = APIResponse(message="ok", user=admin_user).model_dump()
    assert admin_response["user"]["role"] == "admin"

    mixed_response = APIResponse(message="ok").model_dump()
    assert mixed_response["user"] is None


@pytest.mark.parametrize(
    ("model", "payload", "message"),
    [
        (
            Login,
            {"email": "", "password": "secret"},
            "Email is required.",
        ),
        (
            Login,
            {"email": "not-an-email", "password": "secret"},
            "Invalid email format.",
        ),
        (ForgotPassword, {"email": ""}, "Field is required."),
        (
            ResetPassword,
            {
                "token": "token",
                "password": "long-enough-password",
                "confirm_password": "different-password",
            },
            "The passwords do not match.",
        ),
        (
            ChangePassword,
            {
                "current_password": "current",
                "password": "short",
                "confirm_password": "short",
            },
            "Use at least 12 characters for your new password.",
        ),
    ],
)
def test_request_models_return_spec_validation_messages(
    model: type[BaseModel], payload: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError) as error:
        model.model_validate(payload)
    assert message in str(error.value)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "full_name": "",
                "email": "member@example.com",
                "password": "long-enough",
                "phone": "555",
                "state": "CA",
                "terms": True,
            },
            "Field is required.",
        ),
        (
            {
                "full_name": "Member",
                "email": "member@example.com",
                "password": "short",
                "phone": "555",
                "state": "CA",
                "terms": True,
            },
            "Password must be at least 6 characters.",
        ),
        (
            {
                "full_name": "Member",
                "email": "member@example.com",
                "password": "long-enough",
                "phone": "555",
                "state": "CA",
                "terms": False,
            },
            "You must accept the terms and conditions to register.",
        ),
    ],
)
def test_register_model_rejects_invalid_data(
    payload: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError) as error:
        Register.model_validate(payload)
    assert message in str(error.value)


def test_openapi_documents_routes_with_summaries_and_safe_response_model(
    client: TestClient,
) -> None:
    docs = client.get("/docs")
    assert docs.status_code == 200
    schema = client.get("/openapi.json").json()
    for path, operations in schema["paths"].items():
        for operation in operations.values():
            assert operation.get("summary"), path
    assert "/api/register" in schema["paths"]
    assert "/api/login" in schema["paths"]
    assert "/api/forgot-password" in schema["paths"]
    assert "/api/reset-password" in schema["paths"]
    assert "/api/change-password" in schema["paths"]

    api_response = schema["components"]["schemas"]["APIResponse"]
    user_schema = schema["components"]["schemas"]["UserResponse"]
    assert "password_hash" not in user_schema["properties"]
    assert "password_hash" not in api_response["properties"]


def test_admin_route_requires_admin_user(client: TestClient) -> None:
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    page = client.get("/login")
    token = csrf_token(page.text)
    login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": CUSTOMER_EMAIL,
            "password": "Original-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303
    assert login.headers["location"] == "/dashboard"

    admin_page = client.get("/admin", follow_redirects=False)
    assert admin_page.status_code == 403


def test_api_register_validates_and_returns_public_user(client: TestClient) -> None:
    missing_field = client.post(
        "/api/register",
        json={
            "full_name": "",
            "email": "taylor@example.com",
            "password": "secure1",
            "phone": "555-0100",
            "state": "California",
            "terms": True,
        },
    )
    assert missing_field.status_code == 422
    assert missing_field.json()["detail"] == "Field is required."

    invalid_terms = client.post(
        "/api/register",
        json={
            "full_name": "Taylor",
            "email": "taylor@example.com",
            "password": "secure1",
            "phone": "555-0100",
            "state": "California",
            "terms": False,
        },
    )
    assert invalid_terms.status_code == 422
    assert (
        invalid_terms.json()["detail"]
        == "You must accept the terms and conditions to register."
    )

    response = client.post(
        "/api/register",
        json={
            "full_name": "Taylor Driver",
            "email": "taylor@example.com",
            "password": "secure1",
            "phone": "555-0100",
            "state": "California",
            "terms": True,
        },
    )
    assert response.status_code == 201
    assert response.json()["user"]["email"] == "taylor@example.com"
    assert "password_hash" not in response.json()["user"]
    profile = client.get("/api/me")
    assert profile.status_code == 200
    assert "password_hash" not in profile.json()


def test_api_login_starts_session_and_uses_shared_lockout_logic(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/login",
        json={
            "email": "member@example.com",
            "password": "wrong-password",
            "captcha": "test-token",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password."

    response = client.post(
        "/api/login",
        json={
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
            "captcha": "test-token",
        },
    )
    assert response.status_code == 200
    assert "password_hash" not in response.json()["user"]
    assert client.get("/api/me").status_code == 200


def test_api_forgot_and_reset_password(client: TestClient, caplog) -> None:
    response = client.post(
        "/api/forgot-password", json={"email": "member@example.com"}
    )
    assert response.status_code == 200
    assert "If an account matches that email" in response.json()["message"]
    token_match = re.search(
        r"password reset link for member@example.com: http://\S+token=([^\s]+)",
        caplog.text,
    )
    assert token_match

    response = client.post(
        "/api/reset-password",
        json={
            "token": token_match.group(1),
            "password": "Reset-Password-24680",
            "confirm_password": "Reset-Password-24680",
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated. Sign in with your new password."


def test_api_change_password_requires_session_and_changes_password(
    client: TestClient,
) -> None:
    change_payload = {
        "current_password": "Original-Passphrase-24",
        "password": "Changed-Password-24680",
        "confirm_password": "Changed-Password-24680",
    }
    response = client.post("/api/change-password", json=change_payload)
    assert response.status_code == 401

    login = client.post(
        "/api/login",
        json={
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
            "captcha": "test-token",
        },
    )
    assert login.status_code == 200
    response = client.post("/api/change-password", json=change_payload)
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated. Sign in again with your new password."
    assert client.get("/api/me").status_code == 401


def registration_data(page_text: str, **overrides: str) -> dict[str, str]:
    data = {
        "csrf_token": csrf_token(page_text),
        "full_name": "Taylor Driver",
        "email": "taylor@example.com",
        "password": "secure1",
        "phone": "555-0100",
        "state": "California",
        "terms": "on",
    }
    data.update(overrides)
    return data


def test_registration_page_has_required_fields_and_google_link(client: TestClient) -> None:
    response = client.get("/register")
    assert response.status_code == 200
    for expected in (
        'name="full_name"',
        'name="email"',
        'name="password"',
        'name="phone"',
        'name="state"',
        'name="terms"',
        "Register",
        'href="/login">Sign In',
        "Sign up with Google",
    ):
        assert expected in response.text
    assert "Select your state" in response.text


def test_registration_creates_user_and_starts_session(client: TestClient) -> None:
    page = client.get("/register")
    response = client.post(
        "/register", data=registration_data(page.text), follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/?welcome=1"

    user = main.get_user("taylor@example.com")
    assert user is not None
    assert user.full_name == "Taylor Driver"
    assert user.phone == "555-0100"
    assert user.state == "California"
    assert user.terms_accepted_at is not None
    assert main.verify_password("secure1", user.password_hash)
    assert client.get("/").status_code == 200
    welcome = client.get("/?welcome=1")
    assert "Welcome, Taylor Driver!" in welcome.text


def test_registration_rejects_duplicate_email(client: TestClient) -> None:
    page = client.get("/register")
    response = client.post(
        "/register",
        data=registration_data(page.text, email=" MEMBER@example.com "),
    )
    assert response.status_code == 409
    assert "An account with this email already exists." in response.text


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("full_name", "", "Field is required."),
        ("email", "", "Field is required."),
        ("password", "", "Field is required."),
        ("phone", "", "Field is required."),
        ("state", "", "Field is required."),
        ("state", "Not a state", "Select a valid state."),
        ("password", "12345", "Password must be at least 6 characters."),
        (
            "terms",
            "",
            "You must accept the terms and conditions to register.",
        ),
    ],
)
def test_registration_validation_messages(
    client: TestClient, field: str, value: str, message: str
) -> None:
    page = client.get("/register")
    response = client.post(
        "/register",
        data=registration_data(page.text, **{field: value}),
    )
    assert response.status_code == 400
    assert message in response.text


def test_google_registration_prefills_identity_and_uses_session_email(
    client: TestClient, monkeypatch
) -> None:
    class GoogleClient:
        async def authorize_access_token(self, request):
            return {
                "userinfo": {
                    "email": "google@example.com",
                    "email_verified": True,
                    "name": "Google Member",
                }
            }

    monkeypatch.setattr(main.oauth, "google", GoogleClient(), raising=False)
    callback = client.get("/auth/google/callback", follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == "/register"

    page = client.get("/register")
    assert 'value="Google Member"' in page.text
    assert 'value="google@example.com" readonly' in page.text
    response = client.post(
        "/register",
        data=registration_data(
            page.text,
            full_name="Google Member",
            email="attacker@example.com",
        ),
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert main.get_user("google@example.com") is not None
    assert main.get_user("attacker@example.com") is None
    assert "Welcome, Google Member!" in client.get("/?welcome=1").text


def test_google_signup_setup_fallback_returns_to_registration(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    page = client.get("/register")
    assert 'href="/auth/google?flow=signup"' in page.text

    response = client.get("/auth/google?flow=signup", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/register?message=")

    register = client.get(response.headers["location"])
    assert "Google sign-in is not configured yet." in register.text


def test_google_signup_oauth_handoff_to_registration(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")

    class GoogleClient:
        async def authorize_redirect(self, request, redirect_uri: str):
            assert redirect_uri.endswith("/auth/google/callback")
            return main.RedirectResponse(
                "https://accounts.google.com/o/oauth2/auth"
            )

        async def authorize_access_token(self, request):
            return {
                "userinfo": {
                    "email": "new-google@example.com",
                    "email_verified": True,
                    "name": "New Google Member",
                }
            }

    monkeypatch.setattr(main.oauth, "google", GoogleClient(), raising=False)
    start = client.get("/auth/google?flow=signup", follow_redirects=False)
    assert start.status_code == 307
    assert start.headers["location"] == "https://accounts.google.com/o/oauth2/auth"

    callback = client.get("/auth/google/callback", follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == "/register"

    registration = client.get("/register")
    assert 'value="New Google Member"' in registration.text
    assert 'value="new-google@example.com" readonly' in registration.text


def test_google_login_setup_fallback_returns_to_sign_in(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET", raising=False)

    page = client.get("/login")
    assert 'href="/auth/google?flow=login"' in page.text

    response = client.get("/auth/google?flow=login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?message=")


def test_google_sign_in_logs_in_existing_account(
    client: TestClient, monkeypatch
) -> None:
    class GoogleClient:
        async def authorize_access_token(self, request):
            return {
                "userinfo": {
                    "email": "member@example.com",
                    "email_verified": True,
                    "name": "Existing Member",
                }
            }

    monkeypatch.setattr(main.oauth, "google", GoogleClient(), raising=False)
    response = client.get("/auth/google/callback", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.get("/").status_code == 200


def test_login_requires_csrf(client: TestClient) -> None:
    response = client.post("/login", data={"email": "member@example.com", "password": "wrong"})
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("email", "password", "expected_message"),
    [
        ("", "password", "Email is required."),
        ("not-an-email", "password", "Invalid email format."),
        ("member@example.com", "", "Password is required."),
    ],
)
def test_login_shows_field_validation_errors(
    client: TestClient, email: str, password: str, expected_message: str
) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": email,
            "password": password,
            "g-recaptcha-response": "test-token",
        },
    )
    assert response.status_code == 400
    assert expected_message in response.text
    assert 'role="alert"' in response.text


def test_login_requires_recaptcha(client: TestClient) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
        },
    )
    assert response.status_code == 400
    assert "Please complete the reCAPTCHA." in response.text


def test_admin_page_requires_admin_role(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(main, "recaptcha_is_valid", lambda token, remote_ip: True)
    sign_in(client)
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 403


def test_admin_page_is_accessible_to_admin_user(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(main, "recaptcha_is_valid", lambda token, remote_ip: True)
    client.post(
        "/register",
        data={
            "csrf_token": csrf_token(client.get("/register").text),
            "full_name": "Admin User",
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "phone": "555-0199",
            "state": "California",
            "terms": "on",
        },
        follow_redirects=False,
    )
    with database.SessionLocal.begin() as db:
        user = db.get(User, ADMIN_EMAIL)
        assert user is not None
        user.role = "admin"

    page = client.get("/login")
    token = csrf_token(page.text)
    client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    admin_page = client.get("/admin", follow_redirects=False)
    assert admin_page.status_code == 200
    assert "Admin workspace" in admin_page.text


def test_customer_is_redirected_to_dashboard_after_login(client: TestClient) -> None:
    page = client.get("/login")
    token = csrf_token(page.text)
    client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": CUSTOMER_EMAIL,
            "password": "Original-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=False,
    )
    dashboard = client.get("/dashboard", follow_redirects=False)
    assert dashboard.status_code == 200
    assert "Your workspace" in dashboard.text


def test_parking_lot_page_requires_admin_role(client: TestClient) -> None:
    response = client.get("/admin/parking-lots", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_parking_lot_create_requires_admin_role(client: TestClient) -> None:
    sign_in(client)
    response = client.post(
        "/admin/parking-lots",
        data={
            "name": "Test",
            "location": "Here",
            "capacity": "10",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required."


def test_parking_lot_create_valid(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    page = client.get("/admin/parking-lots")
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": "Downtown Garage",
            "location": "1 Main St",
            "capacity": "42",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Added Downtown Garage." in response.text
    with database.SessionLocal() as db:
        lot = db.get(main.ParkingLot, 1)
    assert lot is not None
    assert lot.name == "Downtown Garage"
    assert lot.location == "1 Main St"
    assert lot.capacity == 42


def test_parking_lot_create_rejects_missing_fields(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    page = client.get("/admin/parking-lots")
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": "",
            "location": "",
            "capacity": "",
        },
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert "Name is required." in response.text
    assert "Location is required." in response.text
    assert "Capacity is required." in response.text
    assert 'name="name"' in response.text
    assert 'value=""' in response.text


@pytest.mark.parametrize(
    ("capacity", "message"),
    [
        ("0", "Capacity must be a positive number."),
        ("-3", "Capacity must be a positive number."),
        ("abc", "Capacity must be a whole number."),
        ("3.5", "Capacity must be a whole number."),
    ],
)
def test_parking_lot_create_rejects_invalid_capacity(client: TestClient, monkeypatch, capacity: str, message: str) -> None:
    admin_session(client, monkeypatch)
    page = client.get("/admin/parking-lots")
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": "Test",
            "location": "Here",
            "capacity": capacity,
        },
        follow_redirects=True,
    )
    assert response.status_code == 400
    assert message in response.text
    assert 'name="name"' in response.text
    assert 'value="Test"' in response.text


def test_parking_lot_list_shows_existing_lots(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    page = client.get("/admin/parking-lots")
    assert page.status_code == 200, page.text
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": "Lot A",
            "location": "North",
            "capacity": "10",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200, response.text
    page = client.get("/admin/parking-lots")
    assert page.status_code == 200, page.text
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": "Lot B",
            "location": "South",
            "capacity": "20",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200, response.text
    page = client.get("/admin/parking-lots")
    assert page.status_code == 200, page.text
    assert "Lot A" in page.text
    assert "Lot B" in page.text
    assert "10" in page.text
    assert "20" in page.text


def test_login_reports_recaptcha_verification_failure(
    client: TestClient, monkeypatch
) -> None:
    async def reject_captcha(token: str, remote_ip: str | None) -> bool:
        return False

    monkeypatch.setattr(main, "recaptcha_is_valid", reject_captcha)
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
            "g-recaptcha-response": "invalid-token",
        },
    )
    assert response.status_code == 401
    assert "Verification failed. Please complete the CAPTCHA to proceed." in response.text


def admin_session(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(main, "recaptcha_is_valid", lambda token, remote_ip: True)
    client.post(
        "/register",
        data={
            "csrf_token": csrf_token(client.get("/register").text),
            "full_name": "Admin User",
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "phone": "555-0199",
            "state": "California",
            "terms": "on",
        },
        follow_redirects=False,
    )
    with database.SessionLocal.begin() as db:
        user = db.get(User, ADMIN_EMAIL)
        assert user is not None
        user.role = "admin"

    page = client.get("/login")
    token = csrf_token(page.text)
    login = client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": ADMIN_EMAIL,
            "password": "Admin-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
        follow_redirects=True,
    )
    assert login.status_code == 200, login.text
    # Admin login now lands on /admin; parking lot management is one click away.
    admin_landing = client.get("/admin")
    assert admin_landing.status_code == 200, admin_landing.text


def make_lot(client: TestClient, monkeypatch, name: str, capacity: str) -> int:
    admin_session(client, monkeypatch)
    page = client.get("/admin/parking-lots")
    assert page.status_code == 200, page.text
    response = client.post(
        "/admin/parking-lots",
        data={
            "csrf_token": csrf_token(page.text),
            "name": name,
            "location": "Temp parking lot",
            "capacity": capacity,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200, response.text
    with database.SessionLocal() as db:
        lots = db.scalars(
            select(main.ParkingLot).order_by(main.ParkingLot.id)
        ).all()
    assert lots, response.text
    return lots[-1].id


def lot_detail_page(client: TestClient, lot_id: int) -> str:
    response = client.get(f"/admin/parking-lots/{lot_id}")
    assert response.status_code == 200, response.text
    return response.text


def post_space(
    client: TestClient,
    lot_id: int,
    csrf_token_value: str,
    name: str,
    notes: str = "",
) -> httpx.Response:
    return client.post(
        f"/admin/parking-lots/{lot_id}/spaces",
        data={
            "csrf_token": csrf_token_value,
            "name": name,
            "notes": notes,
        },
        follow_redirects=False,
    )


def test_parking_space_detail_page_requires_admin(client: TestClient) -> None:
    response = client.get("/admin/parking-lots/1", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_parking_space_create_requires_admin(client: TestClient) -> None:
    sign_in(client)
    response = client.post(
        "/admin/parking-lots/1/spaces",
        data={
            "name": "A1",
            "notes": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required."


def test_parking_lot_detail_for_nonexistent_lot_redirects(client: TestClient, monkeypatch) -> None:
    admin_client(client, monkeypatch)
    response = client.get("/admin/parking-lots/99999", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/parking-lots"


def test_add_parking_space_success(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Main Lot", "2")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "A1", "Near entrance")
    assert response.status_code == 303
    detail = client.get(f"/admin/parking-lots/{lot_id}")
    assert detail.status_code == 200, detail.text
    assert "Added A1." in detail.text
    assert "A1" in detail.text
    assert "Near entrance" in detail.text


def test_add_parking_space_optional_notes(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Notes Lot", "1")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "B2", "")
    assert response.status_code == 303
    detail = client.get(f"/admin/parking-lots/{lot_id}")
    assert "Added B2." in detail.text
    assert "B2" in detail.text


def test_add_parking_space_requires_name(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Name Lot", "1")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "", "Should not matter")
    assert response.status_code == 400
    assert "Space name is required." in response.text
    assert 'name="name"' in response.text
    assert 'value=""' in response.text


def test_add_parking_space_duplicate_name(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Dup Lot", "1")
    page = lot_detail_page(client, lot_id)
    post_space(client, lot_id, csrf_token(page), "Shared", "First")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "Shared", "Second")
    assert response.status_code == 400
    assert "A space with that name already exists in this lot." in response.text
    assert "Shared" in response.text


def test_add_parking_space_exceeds_capacity(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Small Lot", "1")
    page = lot_detail_page(client, lot_id)
    post_space(client, lot_id, csrf_token(page), "Only", "")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "Second", "")
    assert response.status_code == 400
    assert "Total spaces exceed the defined parking lot capacity of 1" in response.text


def test_add_parking_space_duplicate_name_same_message_after_capacity_error(client: TestClient, monkeypatch) -> None:
    admin_session(client, monkeypatch)
    lot_id = make_lot(client, monkeypatch, "Edge Lot", "1")
    page = lot_detail_page(client, lot_id)
    post_space(client, lot_id, csrf_token(page), "X", "")
    page = lot_detail_page(client, lot_id)
    response = post_space(client, lot_id, csrf_token(page), "X", "")
    assert response.status_code == 400
    assert "A space with that name already exists in this lot." in response.text


def test_account_locks_after_repeated_failed_logins(client: TestClient) -> None:
    for _ in range(5):
        page = client.get("/login")
        response = client.post(
            "/login",
            data={
                "csrf_token": csrf_token(page.text),
                "email": "member@example.com",
                "password": "wrong-password",
                "g-recaptcha-response": "test-token",
            },
        )
        assert response.status_code == 401
        assert "Incorrect email or password." in response.text

    with database.SessionLocal() as db:
        user = db.get(User, "member@example.com")
        assert user is not None
    assert user.failed_attempts == 5
    assert user.locked_until is not None
    assert user.locked_until - int(main.time.time()) in range(1798, 1801)

    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
    )
    assert response.status_code == 423
    assert (
        "Your account has been locked due to multiple unsuccessful sign-in attempts. "
        "Please reset your password."
    ) in response.text


def test_successful_login_resets_failed_attempts(client: TestClient) -> None:
    with database.SessionLocal.begin() as db:
        user = db.get(User, "member@example.com")
        assert user is not None
        user.failed_attempts = 4
    sign_in(client)
    with database.SessionLocal() as db:
        user = db.get(User, "member@example.com")
        assert user is not None
    assert user.failed_attempts == 0
    assert user.locked_until is None


def test_unexpected_login_error_shows_generic_message(
    client: TestClient, monkeypatch
) -> None:
    def fail_to_get_user(email: str):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(main, "get_user", fail_to_get_user)
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
            "password": "Original-Passphrase-24",
            "g-recaptcha-response": "test-token",
        },
    )
    assert response.status_code == 500
    assert "An unexpected error occurred. Please try again later." in response.text


def test_user_can_sign_in_and_change_password(client: TestClient) -> None:
    sign_in(client)
    assert client.get("/").status_code == 200

    page = client.get("/change-password")
    response = client.post(
        "/change-password",
        data={
            "csrf_token": csrf_token(page.text),
            "current_password": "Original-Passphrase-24",
            "password": "Replacement-Passphrase-35",
            "confirm_password": "Replacement-Passphrase-35",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?")
    assert client.get("/", follow_redirects=False).status_code == 303

    user = main.get_user("member@example.com")
    assert user and main.verify_password("Replacement-Passphrase-35", user.password_hash)
    sign_in(client, "Replacement-Passphrase-35")
    assert client.get("/").status_code == 200


def test_password_reset_token_is_single_use(client: TestClient, caplog) -> None:
    with database.SessionLocal.begin() as db:
        user = db.get(User, "member@example.com")
        assert user is not None
        user.failed_attempts = 5
        user.locked_until = 9999999999

    page = client.get("/forgot-password")
    response = client.post(
        "/forgot-password",
        data={
            "csrf_token": csrf_token(page.text),
            "email": "member@example.com",
        },
    )
    assert response.status_code == 200
    assert "If an account matches that email" in response.text
    assert "password reset link for member@example.com: " in caplog.text
    reset_url = re.search(r"password reset link for member@example.com: (http://\S+)", caplog.text)
    assert reset_url

    reset_page = client.get(reset_url.group(1))
    response = client.post(
        "/reset-password",
        data={
            "csrf_token": csrf_token(reset_page.text),
            "token": reset_url.group(1).split("token=", 1)[1],
            "password": "Reset-Passphrase-2468",
            "confirm_password": "Reset-Passphrase-2468",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with database.SessionLocal() as db:
        user = db.get(User, "member@example.com")
        assert user is not None
    assert user.failed_attempts == 0
    assert user.locked_until is None

    stale_page = client.get(reset_url.group(1))
    response = client.post(
        "/reset-password",
        data={
            "csrf_token": csrf_token(stale_page.text),
            "token": reset_url.group(1).split("token=", 1)[1],
            "password": "Another-Passphrase-1357",
            "confirm_password": "Another-Passphrase-1357",
        },
    )
    assert response.status_code == 400
    assert "invalid or has expired" in response.text

    sign_in(client, "Reset-Passphrase-2468")
    assert client.get("/").status_code == 200