"""Restore only missing files in an identified, pinned PostgreSQL runtime.

No downloads, deletes or overwrites of existing binaries. Incomplete temporary
streams remain in an installation-owned staging directory for inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import uuid
import zipfile


def _digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _inventory_error(error):
    raise error


def _ordinary_entry(path, *, missing_ok=False):
    try:
        metadata=path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata,"st_file_attributes",0) & 0x400:
        raise ValueError("PostgreSQL runtime reparse path refused")
    return metadata


def _ordinary(path):
    for part in (path, *path.parents):
        _ordinary_entry(part,missing_ok=part==path)


def _ensure_directory(path, known):
    if path in known:
        return
    _ensure_directory(path.parent,known)
    try:
        path.mkdir()
    except FileExistsError:
        if not stat.S_ISDIR(_ordinary_entry(path).st_mode):
            raise ValueError("PostgreSQL runtime parent is not a directory")
    known.add(path)


def _atomic_json(path, value):
    temporary=path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value,stream,separators=(",",":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary,path)


def prepare(archive: Path, root: Path) -> dict:
    archive,root=Path(archive).absolute(),Path(root).absolute()
    _ordinary(root)
    if not root.is_dir():
        raise ValueError("PostgreSQL installation root missing")
    marker=root/".saw-postgresql-runtime.json"
    staging=root/".saw-postgresql-stage"
    runtime=root/"pgsql"
    for path in (marker,staging,runtime):
        _ordinary(path)
    pin=_digest(archive)
    owned=False
    if marker.exists():
        if marker.stat().st_size>4096:
            raise ValueError("PostgreSQL runtime ownership marker invalid")
        try:
            previous=json.loads(marker.read_text(encoding="utf-8"))
            owned=(previous["archive_sha256"]==pin and
                   os.path.normcase(previous["root"])==os.path.normcase(str(root)) and
                   previous["state"] in ("preparing","complete"))
        except (KeyError,ValueError,TypeError):
            pass
        if not owned:
            raise ValueError("PostgreSQL runtime belongs to different media or installation")
    elif staging.exists():
        raise ValueError("Unrecognized PostgreSQL runtime staging directory preserved")
    with zipfile.ZipFile(archive) as source:
        files={}
        directories={"pgsql"}
        folded=set()
        total=0
        for entry in source.infolist():
            relative=PurePosixPath(entry.filename.rstrip("/"))
            parts=relative.parts
            if (not parts or parts[0]!="pgsql" or relative.is_absolute() or
                "\\" in entry.filename or any(p in (".","..") or ":" in p or p.endswith((".", " ")) for p in parts) or
                stat.S_ISLNK(entry.external_attr>>16)):
                raise ValueError("PostgreSQL archive path refused")
            key=relative.as_posix()
            if key.casefold() in folded:
                raise ValueError("PostgreSQL archive has duplicate paths")
            folded.add(key.casefold())
            directories.update(p.as_posix() for p in relative.parents if str(p)!=".")
            if entry.is_dir():
                directories.add(key)
            else:
                files[key]=entry
                total+=entry.file_size
        if not files or len(files)>100000 or total>8*1024**3:
            raise ValueError("PostgreSQL archive bounds exceeded")
        existing=set()
        known_directories={root}
        if runtime.exists():
            if not runtime.is_dir():
                raise ValueError("PostgreSQL runtime path is not a directory")
            known_directories.add(runtime)
            for directory, dirs, names in os.walk(runtime, followlinks=False, onerror=_inventory_error):
                for name in dirs:
                    child=Path(directory)/name
                    _ordinary_entry(child)
                    known_directories.add(child)
                    if child.relative_to(root).as_posix() not in directories:
                        raise ValueError("Unknown PostgreSQL runtime directory preserved")
                for name in names:
                    child=Path(directory)/name
                    metadata=_ordinary_entry(child)
                    key=child.relative_to(root).as_posix()
                    if key not in files:
                        raise ValueError("Unknown PostgreSQL runtime file preserved")
                    entry=files[key]
                    with source.open(entry) as stream:
                        expected=hashlib.file_digest(stream,"sha256").hexdigest()
                    if metadata.st_size!=entry.file_size or _digest(child)!=expected:
                        raise ValueError("Modified PostgreSQL runtime file preserved")
                    existing.add(key)
        missing=set(files)-existing
        if existing and missing and not owned:
            raise ValueError("Incomplete PostgreSQL runtime has no ownership marker; files preserved")
        if not missing:
            return {"written":0,"verified":len(existing)}
        state={"archive_sha256":pin,"root":str(root),"state":"preparing"}
        _atomic_json(marker,state)
        staging.mkdir(exist_ok=True)
        written=0
        for key in sorted(missing):
            destination=root/Path(key)
            _ensure_directory(destination.parent,known_directories)
            if _ordinary_entry(destination,missing_ok=True) is not None:
                raise ValueError("PostgreSQL runtime changed during extraction; existing file preserved")
            temporary=staging/(uuid.uuid4().hex+".part")
            with temporary.open("xb") as output, source.open(files[key]) as stream:
                while block:=stream.read(1024*1024):
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            # Windows rename refuses a concurrently created destination.
            if destination.exists():
                raise ValueError("PostgreSQL runtime changed during extraction; staged file retained")
            os.rename(temporary,destination)
            written+=1
        state["state"]="complete"
        _atomic_json(marker,state)
        return {"written":written,"verified":len(files)}


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--archive",type=Path,required=True)
    parser.add_argument("--root",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        result=prepare(args.archive,args.root)
    except (OSError,ValueError,zipfile.BadZipFile):
        print("PostgreSQL runtime verification/recovery refused; existing files preserved")
        return 1
    print(json.dumps(result,separators=(",",":")))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
