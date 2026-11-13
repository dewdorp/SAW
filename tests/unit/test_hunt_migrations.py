"""The additive 0028 and 0029 upgrades create the hunt and AI investigation tables once and keep existing data."""
from sqlalchemy import inspect

from saw.storage.migrate import upgrade
from tests.unit import test_detector_version_migration as fixtures

isolated_engine = fixtures.isolated_engine


def test_0028_and_0029_upgrades_are_additive_and_repeatable(isolated_engine):
    engine = isolated_engine
    assert upgrade(engine, "0027") == "0027"
    before = set(inspect(engine).get_table_names())
    assert not {"hunt_run", "hunt_review", "ai_investigation"} & before
    assert upgrade(engine, "0029") == "0029"
    assert upgrade(engine, "0029") == "0029"
    after = set(inspect(engine).get_table_names())
    assert {"hunt_run", "hunt_review", "ai_investigation"} <= after and before <= after
