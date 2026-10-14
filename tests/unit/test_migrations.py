"""Alembic migrations (adopted from the Codex comparison): head == models, legacy create_all DBs are stamped."""
from __future__ import annotations

import os

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect

from saw.storage.db import Base, load_models, make_engine
from saw.storage.migrate import current, head, upgrade

load_models()


def _diff(engine) -> list:
    with engine.connect() as c:
        ctx = MigrationContext.configure(c, opts={"compare_type": True})
        return compare_metadata(ctx, Base.metadata)


def _urls(tmp_path) -> list[str]:
    urls = [f"sqlite:///{(tmp_path / 'm.db').as_posix()}"]
    if os.environ.get("SAW_TEST_DATABASE_URL"):
        urls.append(os.environ["SAW_TEST_DATABASE_URL"])
    return urls


@pytest.mark.parametrize("which", [0, 1])
def test_fresh_upgrade_matches_models(tmp_path, which):
    urls = _urls(tmp_path)
    if which >= len(urls):
        pytest.skip("SAW_TEST_DATABASE_URL not set")
    eng = make_engine(urls[which])
    Base.metadata.drop_all(eng)
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    assert upgrade(eng) == head()
    assert _diff(eng) == [], "models changed without a migration: run saw.storage.migrate.revision()"


def test_legacy_create_all_database_is_stamped(tmp_path):
    """Servers installed before migrations have the baseline schema (built by create_all) and no version table."""
    eng = make_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    upgrade(eng, "0001")
    with eng.begin() as c:
        c.exec_driver_sql("DROP TABLE alembic_version")
    assert current(eng) is None and "iam_user" in inspect(eng).get_table_names()
    assert upgrade(eng) == head()
    assert _diff(eng) == []


def test_sqlite_upgrade_with_data_keeps_rows_and_foreign_keys(tmp_path):
    """Batch table rebuilds must not trip over foreign keys on a populated SQLite database (analyst-PC upgrades),
    and the pooled connection must enforce foreign keys again afterwards."""
    from alembic import command

    from saw.storage.migrate import _config

    eng = make_engine(f"sqlite:///{(tmp_path / 'u.db').as_posix()}")
    assert upgrade(eng, "0002") == "0002"
    def insert(c, table: str, values: dict) -> None:
        """Fill every NOT NULL column of the 0002 schema, so the test does not depend on column lists."""
        row = dict(values)
        for _cid, name, typ, notnull, default, pk in c.exec_driver_sql(f"PRAGMA table_info({table})").fetchall():
            if name in row or not notnull or default is not None or pk:
                continue
            t = (typ or "").upper()
            row[name] = (0 if any(k in t for k in ("INT", "BOOL", "FLOAT", "REAL", "NUM")) else
                         "2026-10-10 00:00:00" if "DATE" in t or "TIME" in t else "{}" if "JSON" in t else "")
        cols = ", ".join(row)
        c.exec_driver_sql(f"INSERT INTO {table} ({cols}) VALUES ({', '.join('?' for _ in row)})", tuple(row.values()))

    with eng.begin() as c:
        insert(c, "iam_user", {"id": "u1", "username": "a"})
        insert(c, "inv_investigation", {"id": "i1", "display_id": "INV-1", "owner_id": "u1"})
        insert(c, "ev_evidence", {"id": "e1", "investigation_id": "i1", "uploaded_by": "u1", "total_size": 3_000_000_000})
        insert(c, "ev_file", {"id": "f1", "evidence_id": "e1", "display_name": "x", "object_key": "k", "size": 3_000_000_000})
    # a development database: ps_parser was created by create_all while the revision still says 0002
    command.upgrade(_config(eng), "0003")
    command.stamp(_config(eng), "0002")
    assert upgrade(eng) == head()
    with eng.connect() as c:
        assert c.exec_driver_sql("SELECT size FROM ev_file WHERE id='f1'").scalar() == 3000000000
        assert c.exec_driver_sql("SELECT total_size FROM ev_evidence WHERE id='e1'").scalar() == 3000000000
        assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    assert _diff(eng) == []


def test_content_upgrade_keeps_existing_development_tables(tmp_path):
    """Adopting a create_all development schema must retain applied content lineage."""
    eng = make_engine(f"sqlite:///{(tmp_path / 'partial-content.db').as_posix()}")
    assert upgrade(eng, "0012") == "0012"
    binding = Base.metadata.tables["cp_binding"]
    binding.create(eng)
    with eng.begin() as c:
        c.execute(binding.insert().values(kind="sigma", source_id="synthetic", target_id="rule1",
                                         source_version=1, max_source_version=2, payload_digest="f" * 64))
    assert upgrade(eng) == head()
    assert upgrade(eng) == head()
    with eng.connect() as c:
        row = c.execute(binding.select()).mappings().one()
        assert (row["source_version"], row["max_source_version"], row["payload_digest"]) == (1, 2, "f" * 64)
        assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
    assert _diff(eng) == []
