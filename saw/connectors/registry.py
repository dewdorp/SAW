"""Connector configuration (admin-managed), secret handling (write-only, encrypted) and instantiation."""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import JSON, Boolean, DateTime, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw.connectors.base import LogpressoConnector, SecurityDataConnector
from saw.connectors.mock_logpresso import MockLogpressoConnector
from saw.core.security.secrets import decrypt, encrypt
from saw.storage.db import Base, new_id, utcnow

KINDS = {"mock_logpresso": MockLogpressoConnector, "logpresso": LogpressoConnector}
_cache: dict[str, SecurityDataConnector] = {}


class ConnectorConfig(Base):
    __tablename__ = "conn_config"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_health: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def validate_settings(kind: str, settings: dict) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown connector kind {kind}")
    url = settings.get("url")
    if url:
        u = urlparse(url)
        if u.scheme not in ("https",) or not u.hostname:
            raise ValueError("connector url must be https://<internal host>")
        allow = settings.get("_allowlist") or []
        if allow and u.hostname not in allow:
            raise ValueError("connector host not in allowlist")


def to_dict(c: ConnectorConfig) -> dict:
    return {"id": c.id, "name": c.name, "kind": c.kind, "enabled": c.enabled, "settings": c.settings,
            "has_secret": bool(c.secret_enc), "last_health": c.last_health, "updated_at": c.updated_at}


def upsert(s: Session, name: str, kind: str, settings: dict, secret: str | None, enabled: bool = True) -> ConnectorConfig:
    validate_settings(kind, settings)
    c = s.execute(select(ConnectorConfig).where(ConnectorConfig.name == name)).scalar_one_or_none()
    if c is None:
        c = ConnectorConfig(name=name, kind=kind)
        s.add(c)
    c.kind, c.settings, c.enabled, c.updated_at = kind, settings, enabled, utcnow()
    if secret:
        c.secret_enc = encrypt(secret)  # write-only: never returned by the API
    s.flush()
    _cache.pop(c.id, None)
    return c


def get(s: Session, cid: str) -> SecurityDataConnector:
    if cid in _cache:
        return _cache[cid]
    c = s.get(ConnectorConfig, cid)
    if c is None or not c.enabled:
        raise ValueError("connector not found or disabled")
    inst = KINDS[c.kind](c.id, c.settings, decrypt(c.secret_enc) if c.secret_enc else None)
    _cache[c.id] = inst
    return inst


def enabled(s: Session) -> list[ConnectorConfig]:
    return list(s.execute(select(ConnectorConfig).where(ConnectorConfig.enabled.is_(True))).scalars())
