# Northstar Sign-In Portal

A FastAPI starter for account registration, sign-in, password recovery, and password changes, extended with a parking lot management and booking system. Accounts are stored in PostgreSQL through SQLAlchemy 2.0, passwords are hashed with scrypt, browser sessions are signed and time-limited, and form submissions use CSRF tokens.

## Run locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:DATABASE_URL = "postgresql+psycopg://postgres@localhost/parkingdb"
alembic upgrade head
python create_user.py admin@example.com --admin
uvicorn main:app --reload
```

Open http://127.0.0.1:8000. Users can register through `/register`; passwords must be at least 6 characters. Existing accounts can still be provisioned through the CLI.

In local development, reCAPTCHA verification is visibly marked as bypassed. Reset links are written to the application log when email is not configured. Google sign-in is shown but redirects back with a setup message until OAuth credentials are provided.

## Roles and access

| Role | Landing page | Access |
| --- | --- | --- |
| `customer` | `/dashboard` | Browse lots, generate/start/end/cancel their own tickets |
| `admin` | `/admin` | Parking lot and space management, booking management, tickets |

Public registration always creates a `customer`; the role is assigned by the server and a submitted role is never trusted. `python create_user.py <email>` creates a customer and `python create_user.py <email> --admin` creates an administrator. Admin pages, admin JSON endpoints and every parking/booking management route are protected server-side: anonymous visitors are redirected to `/login` (or receive HTTP 401 from JSON APIs) and authenticated non-admins receive HTTP 403.

## Parking and booking behaviour

* **Parking lots** — name, location and a positive capacity. Managed at `/admin/parking-lots`.
* **Parking spaces** — names are unique inside their own lot (enforced by a database constraint) and re-usable across lots. Creating a space that would push a lot past its capacity fails with `Total spaces exceed the defined parking lot capacity of {capacity}`. The lot row is locked inside the transaction so concurrent submissions cannot overshoot the capacity.
* **Bookings (tickets)** — a customer generates a `Pending` booking for an available space, starts it (`Active`, sets `started_at`), ends it (`Completed`, sets `ended_at`) or cancels it (`Cancelled`). Only the owning customer can act on a booking.
* **One open booking per space** — `Pending` and `Active` bookings keep a space occupied; `Completed` and `Cancelled` bookings never do. A partial unique index (`uq_bookings_open_space`) plus row locking prevents concurrent double bookings.
* **Colours** — green when no open booking exists, yellow for `Pending`, red for `Active`. The mapping lives in `models.status_color` / `models.get_space_status` and every grid, panel and API response derives its colour from it.

### Live updates

`GET /api/lots/{id}/spaces` returns each space's id, name, notes, current status, colour and `status_field`. The grids on the admin lot page and the customer lot page poll this endpoint every 5 seconds (`static/app.js`), recolour cards in place, refresh the availability counters, and keep an open detail panel untouched. Polling only starts on pages that contain a grid, skips overlapping requests, pauses while the tab is hidden, and ignores failed requests. The admin tickets page polls `GET /api/admin/tickets` the same way.

### Timezone policy

All booking timestamps are stored and compared as timezone-aware UTC. `datetime-local` input is interpreted as UTC.

## Migrations

```powershell
alembic upgrade head      # apply
alembic downgrade -1      # roll back one revision
alembic current           # show the applied revision
```

`0002_add_user_role` adds `users.role` and backfills existing accounts as `customer`. `0003`–`0005` add parking lots, spaces and bookings. `0006_booking_indexes` adds the booking user index, the open-booking unique index and the `users.role` default. Migrations never drop existing data.

## Provider configuration

Set these environment variables before starting the server:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Long, random signing key for session cookies |
| `DATABASE_URL` | SQLAlchemy PostgreSQL URL; defaults to `postgresql+psycopg://postgres@localhost/signin_auth` |
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

`tests/test_auth.py` covers registration, sign-in, lockout, recovery and role routing. `tests/test_parking_bookings.py` covers the parking and booking rules: capacity limits, per-lot space-name uniqueness, the full ticket lifecycle, ownership checks, CSRF, admin listing/filter/cancel/modify behaviour and the live spaces API. Tests use isolated SQLite databases through the SQLAlchemy ORM; the application itself uses PostgreSQL.
