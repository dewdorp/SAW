"""Deletion adapters reject unsafe paths and incomplete search-engine responses."""
from pathlib import Path
import os
import subprocess
from unittest.mock import Mock

import pytest

from saw.storage.objectstore import LocalFSObjectStore
from saw.storage.opensearch_store import OpenSearchEventStore


@pytest.mark.parametrize("key", ["../sibling/data", "a/../../b", "a//b", "a/./b", "C:/outside", "a/stream:secret"])
def test_deletion_path_rejects_unsafe_keys(tmp_path, key):
    store = LocalFSObjectStore(tmp_path / "objects")
    with pytest.raises(ValueError):
        store.safe_delete_path("saw-evidence-original", key)


def test_cleanup_listing_and_deletion_refuse_junction(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows junction boundary")
    store = LocalFSObjectStore(tmp_path / "objects")
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "private.txt"
    marker.write_text("synthetic", encoding="utf-8")
    link = store.root / "saw-evidence-original" / "inv"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
    assert result.returncode == 0
    with pytest.raises(ValueError):
        store.cleanup_keys("saw-evidence-original", "inv")
    with pytest.raises(ValueError):
        store.delete("saw-evidence-original", "inv/private.txt")
    assert marker.read_text(encoding="utf-8") == "synthetic"


@pytest.mark.parametrize("response", [{"deleted": 1, "failures": [{"cause": "synthetic"}]},
    {"deleted": 1, "timed_out": True}, {"deleted": 1, "version_conflicts": 1}])
def test_opensearch_partial_deletion_is_not_success(response):
    store = OpenSearchEventStore.__new__(OpenSearchEventStore)
    store.client = Mock()
    store.client.delete_by_query.return_value = response
    store.alias, store._dirty = "synthetic-events", False
    with pytest.raises(RuntimeError):
        store.delete_by_evidence("inv-1", "ev-1")
    with pytest.raises(RuntimeError):
        store.delete_by_investigation("inv-1")
    body = store.client.delete_by_query.call_args.kwargs["body"]
    assert "inv-1" in str(body) and "match_all" not in str(body)
