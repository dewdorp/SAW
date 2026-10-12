from __future__ import annotations

import struct

import pytest

from saw.llm.gguf_metadata import read_metadata
from tests.api.test_local_models import gguf_fixture


@pytest.mark.parametrize("payload", [
    b"GGUF" + struct.pack("<IQQ", 3, 1, 2049),
    b"GGUF" + struct.pack("<IQQ", 3, 10001, 1),
    b"GGUF" + struct.pack("<IQQQ", 3, 1, 1, 2**63),
    b"GGUF" + struct.pack("<IQQQ", 3, 1, 1, 2) + b"ab" + struct.pack("<IIQ", 9, 9, 1),
    b"GGUF" + struct.pack("<IQQQ", 3, 1, 1, 2) + b"ab" + struct.pack("<IIQ", 9, 0, 500001),
    b"GGUF" + struct.pack("<IQQ", 3, 1, 1),
])
def test_metadata_limits_fail_before_allocation(tmp_path, payload):
    path = tmp_path / "model.gguf"
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="model_gguf_"):
        read_metadata(path)


def test_metadata_reader_keeps_only_special_tokens(tmp_path):
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf_fixture())
    result = read_metadata(path)
    assert result["tokenizer.ggml.tokens"]["count"] == 128256
    assert len(result["tokenizer.ggml.tokens"]["special"]) == 5


def test_native_file_lock_rejects_concurrent_write(tmp_path):
    import os
    if os.name != "nt":
        pytest.skip("Windows sharing semantics")
    from saw.llm.windows_runtime import _lock_artifacts
    path = tmp_path / "artifact.txt"
    path.write_bytes(b"verified")
    with _lock_artifacts([path]), pytest.raises(OSError):
        path.write_bytes(b"changed")
    assert path.read_bytes() == b"verified"