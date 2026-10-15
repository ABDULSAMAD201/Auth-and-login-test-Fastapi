import re
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[TestClient]:
    monkeypatch.setattr(main, "DATABASE_PATH", tmp_path / "accounts.sqlite3")
    monkeypatch.setattr(main, "APP_ENV", "development")
    monkeypatch.delenv("RECAPTCHA_SITE_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    with TestClient(main.app) as test_client:
        with main.connect_db() as connection:
            connection.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                ("member@example.com", main.hash_password("Original-Passphrase-24")),
            )
        yield test_client


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


def test_five_failed_passwords_lock_account_for_30_minutes(client: TestClient) -> None:
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

    with main.connect_db() as connection:
        user = connection.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE email = ?",
            ("member@example.com",),
        ).fetchone()
    assert user["failed_attempts"] == 5
    assert user["locked_until"] - int(main.time.time()) in range(1798, 1801)

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
    with main.connect_db() as connection:
        connection.execute(
            "UPDATE users SET failed_attempts = 4 WHERE email = ?",
            ("member@example.com",),
        )
    sign_in(client)
    with main.connect_db() as connection:
        user = connection.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE email = ?",
            ("member@example.com",),
        ).fetchone()
    assert user["failed_attempts"] == 0
    assert user["locked_until"] is None


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
    assert user and main.verify_password("Replacement-Passphrase-35", user["password_hash"])
    sign_in(client, "Replacement-Passphrase-35")
    assert client.get("/").status_code == 200


def test_password_reset_token_is_single_use(client: TestClient, caplog) -> None:
    with main.connect_db() as connection:
        connection.execute(
            "UPDATE users SET failed_attempts = 5, locked_until = 9999999999 WHERE email = ?",
            ("member@example.com",),
        )

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
    with main.connect_db() as connection:
        user = connection.execute(
            "SELECT failed_attempts, locked_until FROM users WHERE email = ?",
            ("member@example.com",),
        ).fetchone()
    assert user["failed_attempts"] == 0
    assert user["locked_until"] is None

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