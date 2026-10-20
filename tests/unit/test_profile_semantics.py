"""Only implemented source semantics may be registered."""
import pytest
from pydantic import ValidationError
from saw.source_context.schemas import DeviceProfileInput

def test_unknown_semantic_mapping_rejected():
    with pytest.raises(ValidationError, match="unsupported source semantics"):
        DeviceProfileInput(source_fields={"arbitrary_semantic": "raw.field"})

def test_context_and_time_mapping_contract():
    fields = {k: "raw." + k for k in (
        "org_unit_id", "device_id", "device_profile_version_id", "network", "virtual_domain",
        "timestamp", "start_time", "end_time", "collected_time", "record_kind",
        "session_id", "action", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "duration")}
    assert DeviceProfileInput(source_fields=fields).source_fields == fields
