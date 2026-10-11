from __future__ import annotations

import os

import pyotp
import pytest
from fastapi.testclient import TestClient

from saw.config import Settings
from saw.storage.db import session_scope

PASSWORD = "Str0ng!Passw0rd"


# Run the whole suite against a real OpenSearch with SAW_TEST_OPENSEARCH_URL=http://127.0.0.1:9200
# (indices use the throw-away prefix "sawtest"; never point this at a production cluster).
OPENSEARCH_URL = os.environ.get("SAW_TEST_OPENSEARCH_URL", "")
# ...and/or against PostgreSQL with SAW_TEST_DATABASE_URL=postgresql+psycopg://saw:<pw>@127.0.0.1:5432/saw_test
# (the schema is dropped and recreated for every test: use a dedicated test database).
DATABASE_URL = os.environ.get("SAW_TEST_DATABASE_URL", "")


@pytest.fixture
def settings(tmp_path) -> Settings:
    extra = {"event_store": "opensearch", "opensearch_url": OPENSEARCH_URL,
             "opensearch_index_prefix": "sawtest"} if OPENSEARCH_URL else {}
    if DATABASE_URL:
        from saw.storage import db as _db

        _db.Base.metadata.drop_all(_db.init_db(DATABASE_URL))
    return Settings(
        data_dir=tmp_path,
        database_url=DATABASE_URL or f"sqlite:///{tmp_path / 'saw.db'}",
        event_store_path=str(tmp_path / "events.db"),
        object_store_root=str(tmp_path / "objects"),
        **extra,
    )


@pytest.fixture
def app(settings):
    from saw.apps.api.main import create_app

    return create_app(settings, synchronous_jobs=True)


def make_user(username: str, roles: list[str]) -> str:
    from saw.core.application import identity

    with session_scope() as s:
        return identity.create_user(s, username, PASSWORD, roles).id


class Api:
    """Logged-in test client that attaches the CSRF header automatically."""

    def __init__(self, app, username: str):
        self.c = TestClient(app)
        r = self.c.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        from saw.storage.models import User
        from sqlalchemy import select

        with session_scope() as s:
            u = s.execute(select(User).where(User.username == username)).scalar_one()
            secret = u.mfa_secret
            u.mfa_last_step = None  # tests log the same user in several times within one 30 s code
        r = self.c.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()},
                        headers={"x-csrf-token": self.csrf})
        assert r.status_code == 200, r.text

    def _h(self, kw):
        kw.setdefault("headers", {})["x-csrf-token"] = self.csrf
        return kw

    def get(self, url, **kw):
        return self.c.get("/api/v1" + url, **kw)

    def post(self, url, **kw):
        return self.c.post("/api/v1" + url, **self._h(kw))

    def put(self, url, **kw):
        return self.c.put("/api/v1" + url, **self._h(kw))

    def patch(self, url, **kw):
        return self.c.patch("/api/v1" + url, **self._h(kw))

    def delete(self, url, **kw):
        return self.c.delete("/api/v1" + url, **self._h(kw))


@pytest.fixture
def analyst(app):
    make_user("analyst1", ["analyst"])
    return Api(app, "analyst1")


@pytest.fixture
def senior(app):
    make_user("senior1", ["senior_analyst"])
    return Api(app, "senior1")


@pytest.fixture
def admin(app):
    make_user("admin1", ["admin"])
    return Api(app, "admin1")


@pytest.fixture
def manager(app):
    make_user("manager1", ["soc_manager"])
    return Api(app, "manager1")
