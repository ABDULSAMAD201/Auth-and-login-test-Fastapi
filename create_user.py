import getpass
import sys
from sqlalchemy.exc import IntegrityError

from database import SessionLocal
from main import hash_password
from models import User


def main() -> None:
    args = sys.argv[1:]
    if not args:
        raise SystemExit("Usage: python create_user.py email@example.com [--admin]")

    email = args[0].strip().lower()
    is_admin = "--admin" in args[1:]

    if "@" not in email or len(email) > 254:
        raise SystemExit("Enter a valid email address.")

    password = getpass.getpass("New password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    try:
        with SessionLocal.begin() as db:
            db.add(
                User(
                    email=email,
                    password_hash=hash_password(password),
                    role="admin" if is_admin else "customer",
                )
            )
    except IntegrityError as error:
        raise SystemExit("An account with that email already exists.") from error

    kind = "admin" if is_admin else "customer"
    print(f"Registered {email} as {kind}")


if __name__ == "__main__": 
    main()