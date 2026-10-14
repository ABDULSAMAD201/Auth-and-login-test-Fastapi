import getpass
import sys
from main import connect_db, hash_password, initialize_database


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

    initialize_database()
    try:
        with connect_db() as connection:
            connection.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hash_password(password)),
            )
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise SystemExit("An account with that email already exists.") from error
        raise
    print(f"Registered {email}")


if __name__ == "__main__": 
    main()