"""Native-only generation and legacy PIT reads; synthetic disposable cluster required."""
import io
import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from saw.core.schemas.query import AggRequest
from saw.storage.generations import GenerationRef, GenerationStore, GenerationUnavailable
from saw.storage.opensearch_store import OpenSearchEventStore
from tests.unit.test_event_generation_writers import event, expected

pytestmark = pytest.mark.skipif(
    not os.environ.get("SAW_TEST_OPENSEARCH_URL"),
    reason="dedicated native OpenSearch URL absent",
)


def test_native_retained_reads_and_legacy_pit():
    backend = OpenSearchEventStore(
        os.environ["SAW_TEST_OPENSEARCH_URL"], prefix="sawtest" + uuid.uuid4().hex,
    )
    heads = {}
    store = GenerationStore(
        backend, resolve=lambda inv, generation_id=None: heads.get(inv),
        check_read=lambda ref: None, open_raw=lambda bucket, key: io.BytesIO(b"raw"),
        cursor_key=b"n" * 32,
    )
    backend.index([event()])
    legacy = store.open_view("inv")
    assert legacy.count("inv") == 1
    backend.index([event(1)])
    assert legacy.count("inv") == 1
    assert len(legacy.search("inv", [])["events"]) == 1
    legacy.close()

    def publish(generation, rows):
        ref = GenerationRef("inv", generation, 0, "", store.plan_targets("inv", generation), False)
        args = {"job_id": generation, "attempt": 1, "input_sha256": "a" * 64, "check": lambda: None}
        store.create_target(ref, **args)
        writer = store.begin_write(ref, **args)
        writer.index(rows)
        writer.seal()
        manifest = writer.verify(expected_files=expected(rows), check=lambda: None)
        heads["inv"] = replace(ref, output_sha256=manifest["output_sha256"], head_revision=len(heads) + 1)
        return heads["inv"]

    publish("g1", [event(), event(1)])
    retained = store.open_view("inv")
    current_ref = publish("g2", [event(payload="replacement")])
    assert retained.get("inv", "e000000") == event()
    assert len(retained.search("inv", [])["events"]) == 2
    assert len(list(retained.iterate("inv", [], batch=1))) == 2
    assert retained.count("inv") == 2
    assert retained.aggregate("inv", [], AggRequest(type="count")) == {"value": 2}
    assert retained.group_by("inv", [], ["data_source"], [])[0]["count"] == 2
    assert retained.histogram_metrics("inv", [], None, [])["buckets"][0]["count"] == 2
    assert tuple(datetime.fromisoformat(value) for value in retained.time_bounds("inv")) == (datetime(2026, 1, 1, tzinfo=UTC),) * 2
    current = store.open_view("inv")
    assert current.count("inv") == 1
    assert current.get("inv", "e000000")["payload"] == "replacement"
    backend.client.indices.close(index=current_ref.storage_targets[0])
    with pytest.raises(GenerationUnavailable):
        store.open_view("inv").count("inv")
    assert retained.count("inv") == 2
    current.close()
    retained.close()
