import hashlib
import hmac
import logging
import uvicorn
import os
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from authlib.integrations.starlette_client import OAuth
from fastapi import BackgroundTasks, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

import database
from models import User
from schemas import (
    APIResponse,
    ChangePassword,
    ForgotPassword,
    Login,
    Register,
    ResetPassword,
    UserResponse,
)

BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.getenv("APP_ENV", "development").lower()
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


# i made this function to hash passwords using scrypt, which is a secure password hashing algorithm. It generates a random salt and uses it to hash the password, 
# returning a string that includes the algorithm, salt, and hash. This allows for secure storage of passwords in the database.
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


# rehashes the password and compares it to the stored hash using a constant-time comparison to prevent timing attacks. 
# It returns True if the password is correct, and False otherwise.
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


def create_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token

#now we are defining a function called csrf_is_valid that checks 
# if the CSRF token submitted in a form matches the expected token stored in the user's session.
def csrf_is_valid(request: Request, form: object) -> bool:
    submitted = str(form.get("csrf_token", ""))
    expected = str(request.session.get("csrf_token", ""))
    return bool(expected) and hmac.compare_digest(submitted, expected)


def render(
    request: Request,
    template_name: str,
    context: dict[str, object] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    values = context or {}
    values.setdefault("field_errors", {})
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

#this function retrieves a user from the database based on their email address.
#It connects to the database, executes a query to select the user with the specified email, 
#and returns the user object. If no user is found, it returns None.
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
        if (
            field == "form"
            and "terms and conditions" in message
        ):
            field = "terms"
        field_errors[field] = message
        if first_message == "Field is required." or field == "terms":
            first_message = message
    return field_errors, first_message


def create_registered_user(db: Session, payload: Register) -> User:
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        phone=payload.phone,
        state=payload.state,
        terms_accepted_at=int(time.time()),
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


def change_user_password(
    db: Session, user: User, payload: ChangePassword
) -> bool:
    if not verify_password(payload.current_password, user.password_hash):
        return False
    user.password_hash = hash_password(payload.password)
    user.reset_token_hash = None
    user.reset_expires_at = None
    db.commit()
    return True


#It checks the session for the user's email and expiration time, 
# and verifies that the session version matches the user's session version in the database. If any of these checks fail, 
# it clears the session and returns None. Otherwise, it returns the user object.
def signed_in_user(request: Request):
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


#sends people to /login .Status code 303 means "See Other",
#which tells the client to make a GET request to the new URL.
def redirect_to_login(message: str = "") -> RedirectResponse:
    suffix = f"?{urlencode({'message': message})}" if message else ""
    return RedirectResponse(f"/login{suffix}", status_code=303)


#configures reCAPTCHA by checking 
#if the necessary environment variables for the site key and secret key are set.
def recaptcha_configured() -> bool:
    return bool(os.getenv("RECAPTCHA_SITE_KEY") and os.getenv("RECAPTCHA_SECRET_KEY"))


#asks google to verify the reCAPTCHA token submitted by the user.
#It sends a POST request to the Google reCAPTCHA API with the secret key, the user's response token, and the user's IP address.
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
    

#emails the link or logs it in development mode. It checks if the SMTP_HOST environment variable is set,
#and if not, it logs a warning or error message depending on the environment. If the SMTP_HOST is set, 
# it creates an email message with the reset link and sends it using the SMTP protocol.
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





#session middleware makes request.session work with cookie signed secret key.
#It also sets the session cookie name, max age, same site policy, 
#and whether it should be sent over HTTPS only in production.
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


#OAuth registration sets up google. Security headers adds browser protections.
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
            "welcome_message": (
                f"Welcome, {user.full_name}!"
                if request.query_params.get("welcome")
                else ""
            ),
        },
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
def api_register(payload: Register, request: Request, db: Session = Depends(database.get_db)):
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
    return APIResponse(message=f"Welcome, {user.full_name}!", user=user)


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
    verified = await recaptcha_is_valid(
        payload.captcha, request.client.host if request.client else None
    )
    if not verified:
        return JSONResponse(
            status_code=401,
            content={
                "detail": (
                    "Verification failed. Please complete the CAPTCHA to proceed."
                )
            },
        )
    user, error, status_code = authenticate_user(
        db, payload.email, payload.password
    )
    if error:
        return JSONResponse(status_code=status_code, content={"detail": error})
    assert user is not None
    start_session(request, user, remember=payload.remember)
    return APIResponse(message="Sign in successful.", user=user)


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
            logger.error("PUBLIC_BASE_URL must be configured to send password reset links")
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
            content={
                "detail": "This reset link is invalid or has expired."
            },
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


@app.post("/register", response_class=HTMLResponse, summary="Submit the registration form")
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
                "error": "Your session expired. Please try again.",
                "full_name": full_name,
                "email": email,
                "phone": phone,
                "state": state,
                "google_registration": bool(google_email),
                "states": US_STATES,
            },
            403,
        )

    try:
        payload = Register.model_validate(values)
        if payload.state not in US_STATES:
            raise ValueError("Select a valid state.")
        field_errors = {}
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
    if field_errors:
        return render(request, "register.html", context, 400)

    try:
        with database.SessionLocal() as db:
            user = create_registered_user(db, payload)
    except IntegrityError:
        return render(
            request,
            "register.html",
            {
                **context,
                "error": "An account with this email already exists.",
            },
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
        return render(request, "login.html", {"error": "Your session expired. Please try again."}, 403)

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

        verified = await recaptcha_is_valid(
            payload.captcha, request.client.host if request.client else None
        )
        if not verified:
            return render(
                request,
                "login.html",
                {
                    "error": (
                        "Verification failed. Please complete the CAPTCHA to proceed."
                    ),
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
        return RedirectResponse("/", status_code=303)
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


#checks the csrf token submitted in the form against the expected token stored in the user's session.
#If the tokens do not match, it redirects the user to the login page with an error message. 
# If the tokens match, it clears the user's session and redirects them to the login page with a success message.
@app.post("/logout", summary="Sign out of the current session")
async def logout(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return redirect_to_login("Your session expired. Please try again.")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


#an endpoint to handle GET requests to the /forgot-password URL. It renders the forgot_password.html template, which contains a form for users to request a password reset.
@app.get("/forgot-password", response_class=HTMLResponse, summary="Show password reset request form")
async def forgot_password_page(request: Request):
    return render(request, "forgot_password.html")


@app.post("/forgot-password", response_class=HTMLResponse, summary="Request a password reset link")
async def forgot_password(request: Request, background_tasks: BackgroundTasks):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "forgot_password.html", {"error": "Your session expired. Please try again."}, 403)

    try:
        payload = ForgotPassword.model_validate(
            {"email": str(form.get("email", ""))}
        )
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
            logger.error("PUBLIC_BASE_URL must be configured to send password reset links")

    return render(
        request,
        "forgot_password.html",
        {"success": "If an account matches that email, password reset instructions are on their way."},
    )


@app.get("/reset-password", response_class=HTMLResponse, summary="Show the password reset form")
async def reset_password_page(request: Request, token: str = ""):
    return render(request, "reset_password.html", {"token": token})


@app.post("/reset-password", response_class=HTMLResponse, summary="Submit a password reset")
async def reset_password(request: Request):
    form = await request.form()
    token = str(form.get("token", ""))
    if not csrf_is_valid(request, form):
        return render(request, "reset_password.html", {"token": token, "error": "Your session expired. Please try again."}, 403)
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
            request,
            "reset_password.html",
            {"token": token, "error": message},
            400,
        )

    with database.SessionLocal() as db:
        reset = reset_user_password(db, payload)
    if not reset:
        return render(request, "reset_password.html", {"token": "", "error": "This reset link is invalid or has expired."}, 400)
    request.session.clear()
    return redirect_to_login("Password updated. Sign in with your new password.")


@app.get("/change-password", response_class=HTMLResponse, summary="Show password change form")
async def change_password_page(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    return render(request, "change_password.html")


@app.post("/change-password", response_class=HTMLResponse, summary="Change the signed-in user's password")
async def change_password(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "change_password.html", {"error": "Your session expired. Please try again."}, 403)

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
        return render(request, "change_password.html", {"error": "Your current password is incorrect."}, 400)
    request.session.clear()
    return redirect_to_login("Password updated. Sign in again with your new password.")


@app.get("/auth/google", summary="Start Google sign-in")
async def google_login(request: Request, flow: str = "login"):
    flow = "signup" if flow == "signup" else "login"
    destination = "/register" if flow == "signup" else "/login"
    if not (os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET")):
        query = urlencode({"message": "Google sign-in is not configured yet."})
        return RedirectResponse(f"{destination}?{query}", status_code=303)
    request.session["google_flow"] = flow
    return await oauth.google.authorize_redirect(request, str(request.url_for("google_callback")))


@app.get("/auth/google/callback", name="google_callback", summary="Complete Google sign-in")
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