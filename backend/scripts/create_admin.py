"""Create the first admin account (or another account) from the command line.

There is deliberately NO default admin/admin login. You choose the password
here, it is typed invisibly, validated, and only its Argon2 hash is stored.

Usage (from the backend folder, venv active):
    python -m scripts.create_admin
    python -m scripts.create_admin --username alice --role analyst
"""

import argparse
import getpass
import sys

from pydantic import ValidationError
from sqlalchemy import select

from app import models  # noqa: F401  (registers tables)
from app.core.security import hash_password
from app.db.session import Base, SessionLocal, engine
from app.models import User
from app.models.enums import Role
from app.schemas.user import UserCreate


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a Mini SOC user account.")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--role", choices=[r.value for r in Role], default=Role.ADMIN.value)
    args = parser.parse_args()

    password = getpass.getpass("Password (min 12 characters, input hidden): ")
    if password != getpass.getpass("Repeat password: "):
        print("Error: passwords do not match.", file=sys.stderr)
        return 1

    # Reuse the API's validation rules so the CLI can't create weaker accounts.
    try:
        data = UserCreate(username=args.username, password=password, role=Role(args.role))
    except ValidationError as exc:
        for err in exc.errors():
            print(f"Error: {err['loc'][0]}: {err['msg']}", file=sys.stderr)
        return 1

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == data.username)):
            print(f"Error: user '{data.username}' already exists.", file=sys.stderr)
            return 1
        db.add(User(username=data.username, password_hash=hash_password(data.password), role=data.role))
        db.commit()

    print(f"Created user '{data.username}' with role '{data.role}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
