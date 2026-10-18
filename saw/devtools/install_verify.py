"""Read-only acceptance probe for an existing Windows offline installation.

Invoke this file from verified media with the installation's Python runtime.
It never imports the installed application or starts services, initializes a
database, creates an account, rotates secrets, or prints connection details.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from dotenv import dotenv_values
import psycopg
import yaml


def _private_path(path: Path, root: Path, *, exists: bool = True) -> Path:
    absolute = Path(os.path.abspath(path))
    base = Path(os.path.abspath(root))
    if absolute != base and base not in absolute.parents:
        raise ValueError("outside installation")
    for part in (absolute, *absolute.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("reparse path")
    if exists and not absolute.exists():
        raise ValueError("missing installation path")
    return absolute


def _same_path(value: str, expected: Path) -> bool:
    try:
        return os.path.normcase(os.path.abspath(value)) == os.path.normcase(str(expected.absolute()))
    except (TypeError, ValueError):
        return False


def _configuration(root: Path, pg_port: int, os_port: int) -> tuple[dict, Path]:
    path = _private_path(root / "app/.env", root)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("oversized configuration")
    settings = dotenv_values(stream=io.StringIO(path.read_text(encoding="utf-8-sig")), interpolate=False)
    for key, value in {"SAW_EVENT_STORE": "opensearch", "SAW_OBJECT_STORE": "local",
                       "SAW_SCHEMA_MODE": "migrate"}.items():
        if settings.get(key) != value:
            raise ValueError("unexpected storage profile")
    if settings.get("SAW_COOKIE_SECURE", "").lower() not in ("true", "1"):
        raise ValueError("secure cookies required")
    for key in ("SAW_DATA_DIR", "SAW_OBJECT_STORE_ROOT"):
        path = Path(settings.get(key, ""))
        if not path.is_absolute():
            raise ValueError("absolute storage directory required")
        _private_path(path, root)
        if not path.is_dir():
            raise ValueError("storage directory missing")
    db = urlsplit(settings.get("SAW_DATABASE_URL", ""))
    if (db.scheme != "postgresql+psycopg" or db.hostname != "127.0.0.1" or db.port != pg_port
            or db.username != "saw" or db.path != "/saw" or not db.password or db.query or db.fragment):
        raise ValueError("database profile conflict")
    os_url = urlsplit(settings.get("SAW_OPENSEARCH_URL", ""))
    if (os_url.scheme != "http" or os_url.hostname != "127.0.0.1" or os_url.port != os_port
            or os_url.username or os_url.password or os_url.path not in ("", "/") or os_url.query or os_url.fragment):
        raise ValueError("search profile conflict")
    conf = _private_path(root / "opensearch-2.19.6/config/opensearch.yml", root)
    if conf.stat().st_size > 1024 * 1024:
        raise ValueError("oversized search configuration")
    search = yaml.safe_load(conf.read_text(encoding="utf-8-sig"))
    expected = root / "data/opensearch"
    if not isinstance(search, dict) or not _same_path(search.get("path.data"), expected):
        raise ValueError("search data path conflict")
    _private_path(expected, root)
    return {"user": "saw", "password": unquote(db.password), "dbname": "saw", "port": pg_port}, expected


def _name_matches(host: str, value: str) -> bool:
    host, value = host.rstrip(".").lower(), value.rstrip(".").lower()
    if value.startswith("*."):
        return host.count(".") == value.count(".") and host.endswith(value[1:])
    return host == value


def _tls(root: Path, host: str) -> bool:
    cert_path = _private_path(root / "tls/saw.crt", root)
    key_path = _private_path(root / "tls/saw.key", root)
    if cert_path.stat().st_size > 1024 * 1024 or key_path.stat().st_size > 1024 * 1024:
        return False
    certificates = x509.load_pem_x509_certificates(cert_path.read_bytes())
    if not certificates:
        return False
    cert = certificates[0]
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    public = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(cert.public_key()) != public(key.public_key()):
        return False
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        return False
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        matched = any(_name_matches(host, name) for name in san.get_values_for_type(x509.DNSName))
    else:
        matched = address in san.get_values_for_type(x509.IPAddress)
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in usage:
            return False
    except x509.ExtensionNotFound:
        pass
    return matched


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _health_module():
    # A standalone invocation must use its verified-media sibling, not older
    # application code from the target installation's site-packages.
    path = Path(__file__).with_name("runtime_health.py")
    spec = importlib.util.spec_from_file_location("_saw_install_runtime_health", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_check(*args, **kwargs) -> bool:
    return _health_module().check(*args, **kwargs)


def _search_storage(port: int, expected: Path) -> bool:
    health = _health_module()
    budget = health._Budget(3)
    connection = health._LoopbackHTTPConnection("127.0.0.1", port, timeout=3, budget=budget)
    try:
        connection.request("GET", "/_nodes/settings?filter_path=nodes.*.settings.path.data")
        with connection.getresponse() as response:
            if response.status != 200:
                return False
            raw = response.read(65537)
            if len(raw) > 65536:
                return False
        document = json.loads(raw)
        budget.remaining()
        nodes = document.get("nodes", {})
        if not isinstance(nodes, dict) or len(nodes) != 1:
            return False
        for node in nodes.values():
            paths = node["settings"]["path"]["data"]
            if isinstance(paths, str):
                paths = [paths]
            if not isinstance(paths, list) or len(paths) != 1 or not _same_path(paths[0], expected):
                return False
        return True
    except Exception:
        return False
    finally:
        budget.close()
        connection.close()


def _windows_path_encoding() -> str:
    if os.name != "nt":
        return "utf-8"
    # Match the Windows ANSI path bytes returned by the bundled native server.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetACP.restype = ctypes.c_uint
    return "cp" + str(kernel.GetACP())


def _native_data_path(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        raise ValueError("invalid native directory identity")
    return bytes.fromhex(value).decode(_windows_path_encoding(), errors="strict")


def _database(credentials: dict, schema: str, expected_data: Path, super_password: str) -> bool:
    try:
        with psycopg.connect(host="127.0.0.1", port=credentials["port"], user="postgres",
                             dbname="postgres", password=super_password, connect_timeout=3, client_encoding="UTF8",
                             options="-c default_transaction_read_only=on -c statement_timeout=5000") as identity:
            rows = identity.execute("SELECT encode(pg_catalog.textsend(current_setting('data_directory')), 'hex')").fetchall()
            if len(rows) != 1 or not _same_path(_native_data_path(rows[0][0]), expected_data):
                return False
        with psycopg.connect(host="127.0.0.1", connect_timeout=3, client_encoding="UTF8",
                             options="-c default_transaction_read_only=on -c statement_timeout=5000",
                             **credentials) as connection:
            versions = connection.execute("SELECT version_num FROM alembic_version").fetchall()
            if versions != [(schema,)]:
                return False
            rows = connection.execute(
                "SELECT count(*) FROM iam_user WHERE status='active' AND roles::jsonb ? 'admin'"
            ).fetchall()
            return len(rows) == 1 and rows[0][0] > 0
    except Exception:
        return False


def verify(root: Path, host: str, port: int, pg_port: int, os_port: int, schema: str,
           *, require_live: bool = False) -> dict:
    checks = {}
    result = {"ok": False, "ready": False, "checks": checks}
    root = Path(root).absolute()
    if (not schema or not host or any(type(p) is not int or not 1 <= p <= 65535
                                     for p in (port, pg_port, os_port))
            or len({port, pg_port, os_port}) != 3):
        checks["arguments"] = {"status": "FAIL"}
        return result
    try:
        credentials, search_data = _configuration(root, pg_port, os_port)
        checks["configuration"] = {"status": "PASS"}
    except Exception:
        checks["configuration"] = {"status": "FAIL"}
        return result
    try:
        tls_ok = _tls(root, host)
    except Exception:
        tls_ok = False
    checks["tls"] = {"status": "PASS" if tls_ok else "FAIL"}
    if not tls_ok:
        return result
    active = {name: _listening(p) for name, p in (("database", pg_port), ("opensearch", os_port), ("api", port))}
    for name in active:
        if not active[name]:
            checks[name] = {"status": "NOT_RUN", "reason": "port_not_listening"}
            continue
        if name == "database":
            try:
                secret = _private_path(root / "secrets/postgres-superuser.pw", root)
                if secret.stat().st_size > 1024:
                    raise ValueError("invalid PostgreSQL secret")
                super_password = secret.read_text(encoding="ascii").strip()
                healthy = bool(super_password) and _database(credentials, schema, root / "data/postgresql", super_password)
            except Exception:
                healthy = False
            finally:
                super_password = None
        elif name == "opensearch":
            healthy = _runtime_check("opensearch", os_port) and _search_storage(os_port, search_data)
        else:
            healthy = _runtime_check("api", port, root / "tls/saw.crt", host)
        checks[name] = {"status": "PASS" if healthy else "FAIL"}
    result["ready"] = all(checks[name]["status"] == "PASS" for name in active)
    result["ok"] = result["ready"] or (not require_live and not any(active.values()))
    return result


class _QuietParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid verification arguments")


def main(argv=None) -> int:
    parser = _QuietParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pg-port", type=int, required=True)
    parser.add_argument("--os-port", type=int, required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--require-live", action="store_true")
    try:
        args = parser.parse_args(argv)
        result = verify(args.root, args.host, args.port, args.pg_port, args.os_port, args.schema,
                        require_live=args.require_live)
    except Exception:
        result = {"ok": False, "ready": False, "checks": {"verification": {"status": "FAIL"}}}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
