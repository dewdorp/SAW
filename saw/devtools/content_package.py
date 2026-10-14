"""Create or inspect a data-only content package on a preparation workstation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from saw.content_packages import format as fmt
from saw.content_packages.example import example_document


def _read(path: Path):
    if path.stat().st_size > fmt.MAX_BYTES:
        raise fmt.TooLarge("content file exceeds 1MiB")
    return fmt.read_json(path.read_text(encoding="utf-8"))


def _write(path: Path, document):
    # Exclusive creation avoids silently overwriting the source or a previously sealed revision.
    text = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if len(text.encode("utf-8")) > fmt.MAX_BYTES:
        text = fmt.canonical(document).decode("utf-8") + "\n"
    if len(text.encode("utf-8")) > fmt.MAX_BYTES:
        raise fmt.TooLarge("content file exceeds 1MiB")
    with path.open("x", encoding="utf-8", newline="\n") as output:
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description="Prepare data-only Sigma/parser JSON; no installation or activation.")
    commands = parser.add_subparsers(dest="action", required=True)
    ex = commands.add_parser("example")
    ex.add_argument("output", type=Path)
    build = commands.add_parser("build")
    build.add_argument("source", type=Path)
    build.add_argument("output", type=Path)
    for command in ("verify", "test"):
        sub = commands.add_parser(command)
        sub.add_argument("source", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "example":
            document = example_document()
            _write(args.output, document)
        elif args.action == "build":
            document = fmt.seal(_read(args.source))
            _write(args.output, document)
        else:
            document = fmt.validate(_read(args.source))
        result = {"schema": document["schema"], "package_id": document["package_id"], "revision": document["revision"],
                  "digest": document["payload_sha256"], "items": len(document["entries"]),
                  "integrity": "sha256_verified", "origin": "not_authenticated"}
        if args.action == "test":
            result["test"] = fmt.run_fixtures(document)
        print(json.dumps(result, ensure_ascii=True))
        return 2 if args.action == "test" and not result["test"]["passed"] else 0
    except (ValueError, OSError) as error:
        # Keep logs free of fixture text and paths supplied by content.
        print(json.dumps({"ok": False, "error": type(error).__name__}, ensure_ascii=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
