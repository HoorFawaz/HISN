"""Create the dashboard admin account, or reset its password.

    python -m api.set_password

Run it on the HISN computer. It asks for the username (Enter keeps the current
one) and the new password twice (nothing is shown while typing), and saves a
salted scrypt hash of the password in the database. Restart the dashboard
afterwards so devices signed in with the old password are signed out.
"""

from __future__ import annotations

import getpass
import sys

from api.auth import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    password_problem,
    username_problem,
)
from storage.db import Database


def main(database: Database | None = None) -> int:
    own = database is None
    if database is None:
        from config import settings

        database = Database(settings.db_path)
    try:
        account = database.admin_account()
        current = account.username if account else ""
        try:
            prompt = f"Username [{current}]: " if current else "Username: "
            username = input(prompt).strip() or current
            print(f"New password (at least {MIN_PASSWORD_LENGTH} characters, not shown).")
            password = getpass.getpass("Password: ")
            again = getpass.getpass("Password again: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        problem = username_problem(username) or password_problem(password)
        if problem:
            print(f"Not accepted: {problem}. Nothing was changed.", file=sys.stderr)
            return 1
        if password != again:
            print("The two passwords are different. Nothing was changed.", file=sys.stderr)
            return 1
        database.set_admin(username, hash_password(password))
        print(f"Saved the admin account '{username}'. Restart the dashboard (python -m api.app).")
        return 0
    finally:
        if own:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
