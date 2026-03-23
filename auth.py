"""Authentication and password hashing utilities."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

USER_DB_PATH = Path("users.json")


def _load_users() -> dict[str, str]:
    if not USER_DB_PATH.exists():
        return {}

    with USER_DB_PATH.open("r", encoding="utf-8") as file:
        try:
            users = json.load(file)
        except json.JSONDecodeError:
            return {}

    if not isinstance(users, dict):
        return {}

    return {str(username): str(stored_hash) for username, stored_hash in users.items()}


def _save_users(users: dict[str, str]) -> None:
    with USER_DB_PATH.open("w", encoding="utf-8") as file:
        json.dump(users, file, indent=2)


def hash_password(password: str, salt: str | None = None) -> str:
    """Hash password with SHA-256 and a per-user salt.

    Stored format: salt$hash
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    salt_value = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt_value}{password}".encode("utf-8")).hexdigest()
    return f"{salt_value}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Validate plain password against stored salt$hash format."""
    try:
        salt, expected_hash = stored_hash.split("$", maxsplit=1)
    except ValueError:
        return False

    candidate = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return secrets.compare_digest(candidate, expected_hash)


def register_user(username: str, password: str) -> tuple[bool, str]:
    """Create a user account if username is not already taken."""
    username = (username or "").strip()
    if not username:
        return False, "Username cannot be empty."
    if not password:
        return False, "Password cannot be empty."

    users = _load_users()
    if username in users:
        return False, "Username already exists."

    users[username] = hash_password(password)
    _save_users(users)
    return True, "Registration successful. You can now log in."


def authenticate_user(username: str, password: str) -> tuple[bool, str]:
    """Authenticate user credentials."""
    username = (username or "").strip()
    users = _load_users()

    if username not in users:
        return False, "User does not exist."

    if not verify_password(password, users[username]):
        return False, "Invalid password."

    return True, "Login successful."
