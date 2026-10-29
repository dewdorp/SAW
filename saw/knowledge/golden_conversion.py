"""Finite, nonexecutable conversion contracts and separate evaluator serialization."""
from __future__ import annotations

from saw.knowledge.golden_projection import MAX_CASE, MAX_EXAMPLES, MAX_TOTAL, canonical_bytes, digest

INSTRUCTION = "Use the supplied observations to produce the requested assessment. Distinguish observed facts from uncertainty."


def conversion_record(implementation, input_value, answers):
    if implementation == "input-output-jsonl/1":
        return {"input": input_value, "output": answers}
    if implementation == "messages-jsonl/1":
        return {"messages": [{"role": "system", "content": INSTRUCTION},
            {"role": "user", "content": canonical_bytes(input_value).decode("utf-8")},
            {"role": "assistant", "content": canonical_bytes(answers).decode("utf-8")}]}
    if implementation == "golden-native/1":
        return None
    raise ValueError("golden_unsupported_conversion")


def evaluator_jsonl(examples):
    """Authority belongs to the caller; this never participates in external ZIP creation."""
    chunks, total = [], 0
    for index, example in enumerate(examples):
        if index >= MAX_EXAMPLES:
            raise ValueError("golden_example_limit")
        payload = example["payload"]
        if digest(payload) != example.get("content_sha256"):
            raise ValueError("golden_combined_seal_invalid")
        data = canonical_bytes({"schema": "saw.golden.evaluator-answer.v2",
            "example_id": example["version_id"], "content_sha256": example["content_sha256"],
            "answers": payload["answers"]}, MAX_CASE) + b"\n"
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError("golden_total_byte_limit")
        chunks.append(data)
    return b"".join(chunks)
