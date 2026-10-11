from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# docs/12 §2.1: argon2id m=64MB t=3 p=4
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

MIN_PASSWORD_LEN = 12


class WeakPasswordError(ValueError):
    pass


def validate_password(pw: str) -> None:
    if len(pw) < MIN_PASSWORD_LEN:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    classes = sum(
        [any(c.islower() for c in pw), any(c.isupper() for c in pw), any(c.isdigit() for c in pw),
         any(not c.isalnum() for c in pw)]
    )
    if classes < 3:
        raise WeakPasswordError("password must mix at least 3 of: lower, upper, digit, symbol")


def hash_password(pw: str) -> str:
    validate_password(pw)
    return _hasher.hash(pw)


def verify_password(stored_hash: str, pw: str) -> bool:
    try:
        return _hasher.verify(stored_hash, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
