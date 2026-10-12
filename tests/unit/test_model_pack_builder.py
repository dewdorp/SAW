"""Offline intake tests use synthetic metadata, never real model weights."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.api.test_local_models import pack_fixture


def inputs(tmp_path):
    source, _ = pack_fixture(tmp_path / "source")
    return dict(inbox=tmp_path / "inbox", pack_id="portable-demo", model_id="test/synthetic-llama",
                revision="1" * 40, kind="BASE", quantization="Q4_K_M",
                model=source / "model.gguf", config=source / "config.json",
                tokenizer=source / "tokenizer_config.json", licenses=[source / "LICENSE.txt"])


def test_builder_copies_validated_pack_and_keeps_sources(tmp_path):
    from saw.devtools.model_pack import build_pack
    from saw.llm.model_packs import validate_pack
    args = inputs(tmp_path)
    source_pin = hashlib.sha256(args["model"].read_bytes()).hexdigest()
    result = build_pack(**args)
    output = Path(result["path"])
    assert output == args["inbox"] / args["pack_id"]
    validated = validate_pack(args["pack_id"], SimpleNamespace(llm_models_root=str(args["inbox"])))
    assert validated["manifest_sha256"] == result["manifest_sha256"]
    assert validated["license_status"] == "PENDING_REVIEW"
    assert result["actual_inference"] == "NOT_RUN"
    assert hashlib.sha256(args["model"].read_bytes()).hexdigest() == source_pin
    assert (output / "model.gguf").stat().st_ino != args["model"].stat().st_ino


def test_existing_pack_is_never_overwritten(tmp_path):
    from saw.devtools.model_pack import build_pack
    args = inputs(tmp_path)
    folder = args["inbox"] / args["pack_id"]
    folder.mkdir(parents=True)
    (folder / "keep.txt").write_text("existing")
    with pytest.raises(ValueError, match="model_pack_exists"):
        build_pack(**args)
    assert (folder / "keep.txt").read_text() == "existing"


@pytest.mark.parametrize("mutation", ["identity", "gguf", "template", "traversal", "license"])
def test_invalid_input_never_publishes_a_pack(tmp_path, mutation):
    from saw.devtools.model_pack import build_pack
    args = inputs(tmp_path)
    if mutation == "identity":
        args["model_id"] = "fdtn-ai/Foundation-Sec-8B"
    elif mutation == "gguf":
        args["model"].write_bytes(b"not a model")
    elif mutation == "template":
        args["kind"] = "INSTRUCT"
    elif mutation == "traversal":
        args["pack_id"] = "../escape"
    else:
        args["licenses"] = []
    with pytest.raises(ValueError):
        build_pack(**args)
    assert not (args["inbox"] / "portable-demo").exists()
    assert args["model"].exists()


def test_builder_rejects_source_links(tmp_path):
    import os
    from saw.devtools.model_pack import build_pack
    args = inputs(tmp_path)
    link = tmp_path / "linked.gguf"
    try:
        os.symlink(args["model"], link)
    except OSError:
        pytest.skip("Windows symlink creation is unavailable")
    args["model"] = link
    with pytest.raises(ValueError, match="model_path_"):
        build_pack(**args)


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows directory junction")
@pytest.mark.parametrize("scope", ["source", "inbox"])
def test_builder_rejects_actual_directory_junction(tmp_path, scope):
    import os
    import subprocess
    from saw.devtools.model_pack import build_pack

    args = inputs(tmp_path)
    target = args["model"].parent if scope == "source" else tmp_path / "destination"
    target.mkdir(exist_ok=True)
    link = tmp_path / "junction"
    env = dict(os.environ, SAW_QA_LINK=str(link), SAW_QA_TARGET=str(target))
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command",
        "New-Item -ItemType Junction -Path $env:SAW_QA_LINK -Target $env:SAW_QA_TARGET -ErrorAction Stop | Out-Null"],
        env=env, capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, "Synthetic junction fixture creation failed"
    assert link.is_junction()
    if scope == "source":
        args["model"] = link / "model.gguf"
    else:
        args["inbox"] = link
    with pytest.raises(ValueError, match="model_path_link_rejected"):
        build_pack(**args)
    assert not (tmp_path / "inbox" / "portable-demo").exists()
    assert not (target / "portable-demo").exists()
