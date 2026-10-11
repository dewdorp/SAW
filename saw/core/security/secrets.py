"""Application-level secret encryption (docs/12 §3.2). Key from SAW_SECRET_KEY or a dev key file (KMS/Vault in prod)."""
from __future__ import annotations

import os
from functools import lru_cache

from cryptography.fernet import Fernet

from saw.config import VAR


@lru_cache
def _fernet() -> Fernet:
    key = os.environ.get("SAW_SECRET_KEY")
    if not key:
        f = VAR / "secret.key"  # dev only — production must inject the key (ENV: KMS/Vault)
        f.parent.mkdir(parents=True, exist_ok=True)
        if not f.exists():
            f.write_bytes(Fernet.generate_key())
        key = f.read_text().strip()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()
