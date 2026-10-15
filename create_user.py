import getpass
import sys
from sqlalchemy.exc import IntegrityError

from database import SessionLocal
from main import hash_password
from models import User


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python create_user.py email@example.com")

    email = sys.argv[1].strip().lower()
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
                )
            )
    except IntegrityError as error:
        raise SystemExit("An account with that email already exists.") from error
    print(f"Registered {email}")


if __name__ == "__main__": 
    main()