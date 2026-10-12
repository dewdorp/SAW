"""Bounded GGUF v3 metadata reader; never maps tensors or executes model code.

Types and file-type values follow the pinned llama.cpp gguf constants:
https://github.com/ggml-org/llama.cpp/blob/d81235049384534c167caea52b85a694f6103d14/gguf-py/gguf/constants.py
"""
from __future__ import annotations

import struct

MAX_HEADER = 16 * 1024**2
MAX_ARRAY = 500_000
SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
SPECIAL = {128000: "<|begin_of_text|>", 128001: "<|end_of_text|>",
           128006: "<|start_header_id|>", 128007: "<|end_header_id|>", 128009: "<|eot_id|>"}


def read_metadata(path):
    with path.open("rb") as stream:
        def read(size):
            if size < 0 or stream.tell() + size > MAX_HEADER:
                raise ValueError("model_gguf_header_limit")
            raw = stream.read(size)
            if len(raw) != size:
                raise ValueError("model_gguf_truncated")
            return raw

        def number(fmt):
            return struct.unpack("<" + fmt, read(struct.calcsize(fmt)))[0]

        def string(maximum=1024**2):
            size = number("Q")
            if size > maximum:
                raise ValueError("model_gguf_string_limit")
            try:
                return read(size).decode("utf-8")
            except UnicodeError as exc:
                raise ValueError("model_gguf_string_invalid") from exc

        def scalar(kind):
            if kind == 8:
                return string()
            if kind not in SCALARS:
                raise ValueError("model_gguf_value_type")
            return number(SCALARS[kind])

        if read(4) != b"GGUF" or number("I") != 3:
            raise ValueError("model_gguf_format_unsupported")
        tensors, count = number("Q"), number("Q")
        if not 1 <= tensors <= 10_000 or not 1 <= count <= 2048:
            raise ValueError("model_gguf_count_limit")
        metadata = {}
        for _ in range(count):
            key, kind = string(256), number("I")
            if key in metadata:
                raise ValueError("model_gguf_duplicate_key")
            if kind == 9:
                element, length = number("I"), number("Q")
                if length > MAX_ARRAY or element == 9:
                    raise ValueError("model_gguf_array_limit")
                selected = {}
                for index in range(length):
                    value = scalar(element)
                    if key == "tokenizer.ggml.tokens" and index in SPECIAL:
                        selected[index] = value
                metadata[key] = {"count": length, "element": element, "special": selected}
            else:
                metadata[key] = scalar(kind)
        offsets, names = [], set()
        for _ in range(tensors):
            name, dimensions = string(256), number("I")
            if name in names or not 1 <= dimensions <= 4:
                raise ValueError("model_gguf_tensor_metadata")
            names.add(name)
            for _ in range(dimensions):
                if not 1 <= number("Q") <= 2**32:
                    raise ValueError("model_gguf_tensor_metadata")
            number("I")  # The native loader separately validates tensor type and shape.
            offsets.append(number("Q"))
        alignment = metadata.get("general.alignment", 32)
        if type(alignment) is not int or alignment not in (16, 32, 64, 128, 256):
            raise ValueError("model_gguf_alignment")
        data_start = (stream.tell() + alignment - 1) // alignment * alignment
        if any(offset % alignment or offset >= path.stat().st_size - data_start for offset in offsets):
            raise ValueError("model_gguf_tensor_offset")
        return metadata


def validate_metadata(path, manifest, config, tokenizer):
    data = read_metadata(path)
    tokens = data.get("tokenizer.ggml.tokens")
    quantization = {"Q4_K_M": 15, "Q5_K_M": 17, "Q8_0": 7}
    if (data.get("general.architecture") != "llama" or data.get("general.file_type") != quantization[manifest["quantization"]]
            or data.get("tokenizer.ggml.model") != "gpt2" or data.get("tokenizer.ggml.pre") != "llama-bpe"
            or data.get("tokenizer.ggml.bos_token_id") != 128000 or data.get("tokenizer.ggml.add_bos_token") is False
            or data.get("tokenizer.ggml.add_eos_token") is True
            or not isinstance(tokens, dict) or tokens["element"] != 8 or tokens["count"] != config["vocab_size"]):
        raise ValueError("model_gguf_contract_mismatch")
    kind = manifest["checkpoint_kind"]
    expected = {128000: SPECIAL[128000], 128001: SPECIAL[128001]} if kind == "BASE" else SPECIAL
    if any(tokens["special"].get(key) != value for key, value in expected.items()):
        raise ValueError("model_gguf_special_tokens_mismatch")
    template = data.get("tokenizer.chat_template")
    if kind == "BASE":
        if template or data.get("tokenizer.ggml.eos_token_id") != 128001:
            raise ValueError("model_gguf_base_contract")
    elif (data.get("tokenizer.ggml.eos_token_id") not in (128001, 128009)
          or not isinstance(template, str) or template != tokenizer.get("chat_template")
          or not all(value in template for value in ("<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>"))):
        raise ValueError("model_gguf_instruct_template")
    return data