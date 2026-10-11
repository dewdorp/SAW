"""ObjectStorePort + adapters (docs/09, ADR-0005).

LocalFSObjectStore is the verified local fallback; S3ObjectStore targets MinIO/SeaweedFS (ENV-04).
Keys never contain user-supplied filenames.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Protocol

BUCKETS = (
    "saw-evidence-original",
    "saw-evidence-extracted",
    "saw-artifacts",
    "saw-quarantine",
    "saw-exports",
    "saw-knowledge-attach",
)


class ObjectStorePort(Protocol):
    def put_stream(self, bucket: str, key: str, stream: BinaryIO) -> tuple[int, str]: ...
    def append_part(self, bucket: str, key: str, part_no: int, data: bytes) -> None: ...
    def complete_parts(self, bucket: str, key: str, part_numbers: list[int]) -> tuple[int, str]: ...
    def open(self, bucket: str, key: str) -> BinaryIO: ...
    def local_path(self, bucket: str, key: str) -> Path: ...
    def exists(self, bucket: str, key: str) -> bool: ...
    def delete(self, bucket: str, key: str) -> None: ...
    def read_range(self, bucket: str, key: str, offset: int, length: int) -> bytes: ...


LONG_PREFIX = "\\\\?\\"


def _check_key(key: str) -> None:
    parts = key.split("/")
    if not key or key.startswith("/") or ".." in parts or "\\" in key or "\x00" in key:
        raise ValueError("invalid object key")


class LocalFSObjectStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        for b in BUCKETS:
            (self.root / b).mkdir(parents=True, exist_ok=True)

    def _path(self, bucket: str, key: str) -> Path:
        if bucket not in BUCKETS:
            raise ValueError(f"unknown bucket {bucket}")
        _check_key(key)
        p = (self.root / bucket / key).resolve()
        if not str(p).startswith(str((self.root / bucket).resolve())):
            raise ValueError("key escapes bucket")
        if os.name == "nt" and len(str(p)) > 240 and not str(p).startswith(LONG_PREFIX):
            p = Path(LONG_PREFIX + str(p))  # Windows long-path prefix
        return p

    def put_stream(self, bucket: str, key: str, stream: BinaryIO) -> tuple[int, str]:
        p = self._path(bucket, key)
        p.parent.mkdir(parents=True, exist_ok=True)
        h, n = hashlib.sha256(), 0
        with open(p, "wb") as f:
            while chunk := stream.read(1024 * 1024):
                h.update(chunk)
                n += len(chunk)
                f.write(chunk)
        return n, h.hexdigest()

    def put_bytes(self, bucket: str, key: str, data: bytes) -> tuple[int, str]:
        import io

        return self.put_stream(bucket, key, io.BytesIO(data))

    def append_part(self, bucket: str, key: str, part_no: int, data: bytes) -> None:
        p = self._path(bucket, f"{key}.parts/{part_no:06d}")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def complete_parts(self, bucket: str, key: str, part_numbers: list[int]) -> tuple[int, str]:
        p = self._path(bucket, key)
        parts_dir = self._path(bucket, f"{key}.parts/x").parent
        h, n = hashlib.sha256(), 0
        with open(p, "wb") as out:
            for no in sorted(part_numbers):
                data = (parts_dir / f"{no:06d}").read_bytes()
                h.update(data)
                n += len(data)
                out.write(data)
        shutil.rmtree(parts_dir, ignore_errors=True)
        return n, h.hexdigest()

    def open(self, bucket: str, key: str) -> BinaryIO:
        return open(self._path(bucket, key), "rb")

    def local_path(self, bucket: str, key: str) -> Path:
        return self._path(bucket, key)

    def exists(self, bucket: str, key: str) -> bool:
        return self._path(bucket, key).exists()

    def delete(self, bucket: str, key: str) -> None:
        self._path(bucket, key).unlink(missing_ok=True)

    def read_range(self, bucket: str, key: str, offset: int, length: int) -> bytes:
        with open(self._path(bucket, key), "rb") as f:
            f.seek(offset)
            return f.read(length)

    def iter_keys(self, bucket: str, prefix: str = "") -> Iterator[str]:
        base = self.root / bucket
        for p in base.rglob("*"):
            if p.is_file():
                k = p.relative_to(base).as_posix()
                if k.startswith(prefix):
                    yield k


class S3ObjectStore:  # pragma: no cover - ENV-04 (requires MinIO/SeaweedFS)
    """S3-compatible adapter. Multipart parts are uploaded directly via the S3 multipart API."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, scratch: str | Path):
        import boto3

        self.s3 = boto3.client(
            "s3", endpoint_url=endpoint, aws_access_key_id=access_key, aws_secret_access_key=secret_key
        )
        self.scratch = Path(scratch)
        self._uploads: dict[str, tuple[str, dict[int, str]]] = {}

    def put_stream(self, bucket: str, key: str, stream: BinaryIO) -> tuple[int, str]:
        _check_key(key)
        h = hashlib.sha256()
        data = stream.read()
        h.update(data)
        self.s3.put_object(Bucket=bucket, Key=key, Body=data, Metadata={"sha256": h.hexdigest()})
        return len(data), h.hexdigest()

    def append_part(self, bucket: str, key: str, part_no: int, data: bytes) -> None:
        _check_key(key)
        if key not in self._uploads:
            up = self.s3.create_multipart_upload(Bucket=bucket, Key=key)
            self._uploads[key] = (up["UploadId"], {})
        upload_id, etags = self._uploads[key]
        r = self.s3.upload_part(Bucket=bucket, Key=key, PartNumber=part_no, UploadId=upload_id, Body=data)
        etags[part_no] = r["ETag"]

    def complete_parts(self, bucket: str, key: str, part_numbers: list[int]) -> tuple[int, str]:
        upload_id, etags = self._uploads.pop(key)
        self.s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": [{"PartNumber": n, "ETag": etags[n]} for n in sorted(part_numbers)]},
        )
        h, n = hashlib.sha256(), 0
        body = self.s3.get_object(Bucket=bucket, Key=key)["Body"]
        for chunk in iter(lambda: body.read(1024 * 1024), b""):
            h.update(chunk)
            n += len(chunk)
        return n, h.hexdigest()

    def open(self, bucket: str, key: str) -> BinaryIO:
        return self.s3.get_object(Bucket=bucket, Key=key)["Body"]

    def local_path(self, bucket: str, key: str) -> Path:
        p = self.scratch / bucket / key
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            self.s3.download_file(bucket, key, str(p))
        return p

    def exists(self, bucket: str, key: str) -> bool:
        try:
            self.s3.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def delete(self, bucket: str, key: str) -> None:
        self.s3.delete_object(Bucket=bucket, Key=key)

    def read_range(self, bucket: str, key: str, offset: int, length: int) -> bytes:
        r = self.s3.get_object(Bucket=bucket, Key=key, Range=f"bytes={offset}-{offset + length - 1}")
        return r["Body"].read()
