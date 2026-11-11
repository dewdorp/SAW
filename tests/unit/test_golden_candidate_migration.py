"""The additive 0026 upgrade creates the golden-set candidate table once and keeps existing data."""
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from saw.storage.migrate import upgrade
from saw.storage.models import Investigation, User
from tests.unit import test_detector_version_migration as fixtures

isolated_engine = fixtures.isolated_engine
TABLES = {"kn_golden_candidate"}


def test_0026_upgrade_is_additive_and_repeatable(isolated_engine):
    engine = isolated_engine
    assert upgrade(engine, "0025") == "0025"
    with Session(engine) as session:
        session.add(User(id="author", username="synthetic", password_hash="", roles=["analyst"]))
        session.flush()
        session.add(Investigation(id="inv", display_id="INV-SYNTHETIC", title="Synthetic", owner_id="author"))
        session.commit()
    assert not TABLES & set(inspect(engine).get_table_names())
    assert upgrade(engine, "0026") == "0026"
    assert upgrade(engine, "0026") == "0026"
    assert TABLES <= set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT title FROM inv_investigation WHERE id='inv'")).scalar() == "Synthetic"
