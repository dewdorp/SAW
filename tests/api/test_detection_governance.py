"""Governed rule changes preserve active content and immutable payloads."""
import pytest
from sqlalchemy import select

from saw.detection.service import Detection, DetectionVersion
from saw.storage.db import session_scope
from tests.api.test_content_packages import prepared, apply, document


def applied_rule(analyst, senior):
    package = prepared(analyst)
    response = apply(senior, package)
    assert response.status_code == 200, response.text
    with session_scope() as s:
        row = s.scalar(select(Detection))
        return row.id, package


def test_package_activation_and_manual_draft_have_independent_pointers(analyst, senior):
    ident, _ = applied_rule(analyst, senior)
    original = analyst.get(f"/detections/{ident}").json()
    assert original["pointers"]["active"]["version"] == 1
    assert original["pointers"]["draft"] is None
    changed = analyst.patch(f"/detections/{ident}", json={"title": "Synthetic draft two"}).json()
    assert changed["pointers"]["draft"]["version"] == 2
    assert changed["pointers"]["active"] == original["pointers"]["active"]
    assert changed["pointers"]["approved"] == original["pointers"]["approved"]
    assert changed["pointers"]["activation_revision"] == original["pointers"]["activation_revision"]


def test_next_package_revision_preserves_an_existing_manual_draft(analyst, senior):
    ident, _ = applied_rule(analyst, senior)
    draft = analyst.patch(f"/detections/{ident}", json={"description": "Keep synthetic draft"}).json()
    package = prepared(analyst, document(2))
    response = apply(senior, package)
    assert response.status_code == 200, response.text
    row = analyst.get(f"/detections/{ident}").json()
    assert row["pointers"]["active"]["version"] == 3
    assert row["pointers"]["draft"]["id"] == draft["pointers"]["draft"]["id"]
    assert row["current"]["description"] == "Keep synthetic draft"


def test_rule_payload_cannot_be_mutated_in_place(analyst, senior):
    ident, _ = applied_rule(analyst, senior)
    with pytest.raises(ValueError, match="immutable"):
        with session_scope() as s:
            version = s.scalar(select(DetectionVersion).where(DetectionVersion.detection_id == ident))
            version.logic = version.logic.replace("/synthetic-sensitive", "/changed")
            s.flush()
