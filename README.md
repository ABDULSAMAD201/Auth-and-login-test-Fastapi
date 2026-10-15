# Northstar Sign-In Portal

A FastAPI starter for registered-user sign-in, password recovery, and password changes. Accounts are stored in SQLite, passwords are hashed with scrypt, browser sessions are signed and time-limited, and form submissions use CSRF tokens.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python create_user.py you@example.com
uvicorn main:app --reload
```

Open http://127.0.0.1:8000. Users can register through `/register`; passwords must be at least 6 characters. Existing accounts can still be provisioned through the CLI.

In local development, reCAPTCHA verification is visibly marked as bypassed. Reset links are written to the application log when email is not configured. Google sign-in is shown but redirects back with a setup message until OAuth credentials are provided.

## Provider configuration

Set these environment variables before starting the server:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Long, random signing key for session cookies |
| `DATABASE_PATH` | Optional SQLite database path; defaults to `accounts.db` |
| `APP_ENV` | Set to `production` to require HTTPS cookies and reCAPTCHA verification |
| `PUBLIC_BASE_URL` | Canonical public origin used in password reset links, e.g. `https://portal.example.com` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth web client credentials; register `/auth/google/callback` as the redirect URI |
| `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY` | Google reCAPTCHA v2 checkbox site and secret keys |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server for reset emails; defaults to port 587 |
| `SMTP_USER` / `SMTP_PASSWORD` | Optional SMTP credentials |
| `SMTP_FROM` | Optional sender address; defaults to `SMTP_USER` |

For production, configure HTTPS at the reverse proxy, set a stable `SECRET_KEY` and `PUBLIC_BASE_URL`, Google OAuth and reCAPTCHA credentials, and SMTP delivery. The reset endpoint intentionally returns the same message whether an account exists or not. Google sign-in logs in existing accounts and guides new Google users through registration.

## Test

```powershell
pytest
```