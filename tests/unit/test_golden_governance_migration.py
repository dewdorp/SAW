"""Populated upgrades preserve v1 bytes and repair only missing governance indexes."""
import importlib
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from saw.storage.db import make_engine
from saw.storage.migrate import upgrade


def test_0021_populated_v1_upgrade_twice_keeps_bytes_and_repairs_index(tmp_path):
    engine = make_engine(f"sqlite:///{(tmp_path / 'golden.db').as_posix()}")
    upgrade(engine, "0020")
    with engine.begin() as c:
        c.execute(text("INSERT INTO kn_experience (id,display_id,status,data,analyst_id,analyst_name,review_comment,rev,deprecated,views,helpful,created_at,updated_at) VALUES ('exp','EXP-1','approved','{\"legacy\":\"exact\"}','author','author','',1,0,0,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        c.execute(text("INSERT INTO kn_golden_blob (sha256,content,size_bytes,masking_version,created_at) VALUES (:sha,:content,14,'golden-mask-v1',CURRENT_TIMESTAMP)"),
                  {"sha": "a" * 64, "content": '{"legacy":true}'})
        c.execute(text("INSERT INTO kn_golden_version (id,experience_id,experience_rev,version,source_investigation_id,status,methodology_version,as_of,input,answers,manifest,metadata_json,content_sha256,author_id,contributor_ids,confirmations,created_at) VALUES ('g','exp',1,1,'source','draft','legacy',CURRENT_TIMESTAMP,:input,:answers,:manifest,:metadata,:sha,'author',:contributors,:confirmations,CURRENT_TIMESTAMP)"),
                  {"input": '{"schema":"saw.golden.agent-input.v1"}', "answers": '{"legacy":"answer"}',
                   "manifest": '[]', "metadata": '{"title":"Legacy"}', "sha": "b" * 64,
                   "contributors": '["author"]', "confirmations": '{}'})
        before = tuple(c.execute(text("SELECT input,answers,manifest,metadata_json,content_sha256 FROM kn_golden_version")).one())
        blob = tuple(c.execute(text("SELECT content,sha256 FROM kn_golden_blob")).one())
    upgrade(engine, "0021")
    migration = importlib.import_module("saw.storage.migrations.versions.0021_golden_governance")
    with engine.begin() as c:
        c.exec_driver_sql("DROP INDEX ix_kn_golden_release_source_investigation_id")
        with Operations.context(MigrationContext.configure(c)):
            migration.upgrade()
            migration.upgrade()
        assert tuple(c.execute(text("SELECT input,answers,manifest,metadata_json,content_sha256 FROM kn_golden_version")).one()) == before
        assert tuple(c.execute(text("SELECT content,sha256 FROM kn_golden_blob")).one()) == blob
    assert "ix_kn_golden_release_source_investigation_id" in {
        x["name"] for x in inspect(engine).get_indexes("kn_golden_release_source")}
    engine.dispose()
