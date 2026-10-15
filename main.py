import hashlib
import hmac
import logging
import uvicorn
import os
import re
import secrets
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlencode

import httpx
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from authlib.integrations.starlette_client import OAuth
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

import database
from models import User

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


@app.get("/", response_class=HTMLResponse)
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


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
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
        },
    )


@app.post("/register", response_class=HTMLResponse)
async def register(request: Request):
    form = await request.form()
    google_registration = request.session.get("google_registration", {})
    google_email = str(google_registration.get("email", "")).strip().lower()
    full_name = str(form.get("full_name", "")).strip()
    if google_email and not full_name:
        full_name = str(google_registration.get("name", "")).strip()
    email = google_email or str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    phone = str(form.get("phone", "")).strip()
    state = str(form.get("state", "")).strip()

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

    field_errors: dict[str, str] = {}
    for field, value in (
        ("full_name", full_name),
        ("email", email),
        ("password", password),
        ("phone", phone),
        ("state", state),
    ):
        if not value:
            field_errors[field] = "Field is required."
    terms_accepted = form.get("terms") == "on"
    if not terms_accepted:
        field_errors["terms"] = (
            "You must accept the terms and conditions to register."
        )
    if password and len(password) < 6:
        field_errors["password"] = "Password must be at least 6 characters."
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        field_errors["email"] = "Invalid email format."
    if state and state not in US_STATES:
        field_errors["state"] = "Select a valid state."

    context: dict[str, object] = {
        "field_errors": field_errors,
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "state": state,
        "terms_checked": terms_accepted,
        "google_registration": bool(google_email),
        "states": US_STATES,
    }
    if field_errors:
        return render(request, "register.html", context, 400)

    try:
        with database.SessionLocal() as db:
            user = User(
                email=email,
                password_hash=hash_password(password),
                full_name=full_name,
                phone=phone,
                state=state,
                terms_accepted_at=int(time.time()),
            )
            db.add(user)
            db.commit()
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


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, message: str = ""):
    if signed_in_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"message": message})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "login.html", {"error": "Your session expired. Please try again."}, 403)

    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    field_errors: dict[str, str] = {}
    if not email:
        field_errors["email"] = "Email is required."
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        field_errors["email"] = "Invalid email format."
    if not password:
        field_errors["password"] = "Password is required."
    if field_errors:
        return render(
            request,
            "login.html",
            {"field_errors": field_errors, "email_value": email},
            400,
        )

    captcha = str(form.get("g-recaptcha-response", ""))
    if not captcha:
        return render(
            request,
            "login.html",
            {"error": "Please complete the reCAPTCHA.", "email_value": email},
            400,
        )

    try:
        user = get_user(email)
        now = int(time.time())
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
            captcha, request.client.host if request.client else None
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

        if not user or not verify_password(password, user.password_hash):
            if user:
                failed_attempts = int(user.failed_attempts or 0)
                if user.locked_until is not None and user.locked_until <= now:
                    failed_attempts = 0
                failed_attempts += 1
                locked_until = (
                    now + SIGN_IN_LOCKOUT_LENGTH
                    if failed_attempts >= SIGN_IN_MAX_FAILED_ATTEMPTS
                    else None
                )
                with database.SessionLocal.begin() as db:
                    db.execute(
                        update(User)
                        .where(User.email == email)
                        .values(
                            failed_attempts=failed_attempts,
                            locked_until=locked_until,
                        )
                    )
            return render(
                request,
                "login.html",
                {"error": "Incorrect email or password.", "email_value": email},
                401,
            )

        with database.SessionLocal.begin() as db:
            db.execute(
                update(User)
                .where(User.email == email)
                .values(failed_attempts=0, locked_until=None)
            )

        start_session(request, user, remember=form.get("remember") == "on")
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
@app.post("/logout")
async def logout(request: Request):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return redirect_to_login("Your session expired. Please try again.")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


#an endpoint to handle GET requests to the /forgot-password URL. It renders the forgot_password.html template, which contains a form for users to request a password reset.
@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return render(request, "forgot_password.html")


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request, background_tasks: BackgroundTasks):
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "forgot_password.html", {"error": "Your session expired. Please try again."}, 403)

    email = str(form.get("email", "")).strip().lower()
    user = get_user(email)
    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with database.SessionLocal.begin() as db:
            db.execute(
                update(User)
                .where(User.email == email)
                .values(
                    reset_token_hash=token_hash,
                    reset_expires_at=int(time.time()) + RESET_TOKEN_LENGTH,
                )
            )
        public_base_url = os.getenv("PUBLIC_BASE_URL")
        if public_base_url or APP_ENV != "production":
            base_url = (public_base_url or str(request.base_url)).rstrip("/")
            reset_url = f"{base_url}/reset-password?token={raw_token}"
            background_tasks.add_task(send_reset_email, email, reset_url)
        else:
            logger.error("PUBLIC_BASE_URL must be configured to send password reset links")

    return render(
        request,
        "forgot_password.html",
        {"success": "If an account matches that email, password reset instructions are on their way."},
    )


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = ""):
    return render(request, "reset_password.html", {"token": token})


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password(request: Request):
    form = await request.form()
    token = str(form.get("token", ""))
    if not csrf_is_valid(request, form):
        return render(request, "reset_password.html", {"token": token, "error": "Your session expired. Please try again."}, 403)
    new_password = str(form.get("password", ""))
    confirmation = str(form.get("confirm_password", ""))
    if len(new_password) < 12:
        return render(request, "reset_password.html", {"token": token, "error": "Use at least 12 characters for your new password."}, 400)
    if new_password != confirmation:
        return render(request, "reset_password.html", {"token": token, "error": "The passwords do not match."}, 400)

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with database.SessionLocal.begin() as db:
        user = db.scalar(
            select(User).where(
                User.reset_token_hash == token_hash,
                User.reset_expires_at > int(time.time()),
            )
        )
        if not user:
            return render(request, "reset_password.html", {"token": "", "error": "This reset link is invalid or has expired."}, 400)
        db.execute(
            update(User)
            .where(User.email == user.email)
            .values(
                password_hash=hash_password(new_password),
                reset_token_hash=None,
                reset_expires_at=None,
                failed_attempts=0,
                locked_until=None,
            )
        )
    request.session.clear()
    return redirect_to_login("Password updated. Sign in with your new password.")


@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    return render(request, "change_password.html")


@app.post("/change-password", response_class=HTMLResponse)
async def change_password(request: Request):
    user = signed_in_user(request)
    if not user:
        return redirect_to_login("Please sign in to change your password.")
    form = await request.form()
    if not csrf_is_valid(request, form):
        return render(request, "change_password.html", {"error": "Your session expired. Please try again."}, 403)

    current_password = str(form.get("current_password", ""))
    new_password = str(form.get("password", ""))
    confirmation = str(form.get("confirm_password", ""))
    if not verify_password(current_password, user.password_hash):
        return render(request, "change_password.html", {"error": "Your current password is incorrect."}, 400)
    if len(new_password) < 12:
        return render(request, "change_password.html", {"error": "Use at least 12 characters for your new password."}, 400)
    if new_password != confirmation:
        return render(request, "change_password.html", {"error": "The passwords do not match."}, 400)

    with database.SessionLocal.begin() as db:
        db.execute(
            update(User)
            .where(User.email == user.email)
            .values(
                password_hash=hash_password(new_password),
                reset_token_hash=None,
                reset_expires_at=None,
            )
        )
    request.session.clear()
    return redirect_to_login("Password updated. Sign in again with your new password.")


@app.get("/auth/google")
async def google_login(request: Request):
    if not (os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET")):
        return redirect_to_login("Google sign-in is not configured yet.")
    return await oauth.google.authorize_redirect(request, str(request.url_for("google_callback")))


@app.get("/auth/google/callback", name="google_callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        profile = token.get("userinfo") or await oauth.google.userinfo(token=token)
    except Exception:
        logger.exception("Google OAuth callback failed")
        return redirect_to_login("Google sign-in could not be completed.")

    email = str(profile.get("email", "")).strip().lower()
    if not email or not profile.get("email_verified"):
        return redirect_to_login("Google could not verify your email address.")
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