"""Admin CLI: `python -m saw.cli create-user <username> --role analyst [--password ...]`."""
from __future__ import annotations

import argparse
import getpass
import sys

from saw import container
from saw.core.application import audit, identity
from saw.storage.db import session_scope


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Korean Windows consoles default to cp949
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(prog="saw")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--role", action="append", required=True)
    cu.add_argument("--password", help="avoid: visible in the process list; prefer --password-file or the prompt")
    cu.add_argument("--password-file", help="read the password from this file (installer use)")
    cu.add_argument("--display-name", default="")
    cu.add_argument("--if-missing", action="store_true", help="do nothing (exit 0) when the user already exists")
    sub.add_parser("verify-audit")
    ai = sub.add_parser("attack-import", help="build data/mitre/enterprise-attack.compact.json from an official STIX bundle")
    ai.add_argument("bundle")
    ai.add_argument("--sha256", required=True, help="expected SHA-256 of the bundle (from the pinned release)")
    ai.add_argument("--source", default="")
    sub.add_parser("migrate", help="apply database schema migrations (Alembic upgrade head)")
    sv = sub.add_parser("serve", help="run API + web UI (production: single process, HTTPS)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8443)
    sv.add_argument("--cert", help="TLS certificate (PEM)")
    sv.add_argument("--key", help="TLS private key (PEM)")
    rm = sub.add_parser("reset-mfa")
    rm.add_argument("username")
    sp = sub.add_parser("set-password", help="set a temporary password (prompted; never pass it on the command line)")
    sp.add_argument("username")
    mc = sub.add_parser("make-cert", help="self-signed TLS certificate (when no internal CA is available)")
    mc.add_argument("--name", action="append", required=True, help="DNS name or IP (repeatable)")
    mc.add_argument("--out", default="var/tls")
    mc.add_argument("--days", type=int, default=825)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        return serve(a)
    if a.cmd == "attack-import":
        from saw.attack.stix_import import build_compact, write_compact

        cat = build_compact(a.bundle, a.sha256, a.source)
        out = write_compact(cat)
        print(f"ATT&CK {cat['attack_version']}: {len(cat['techniques'])} techniques, {len(cat['tactics'])} tactics -> {out}")
        return 0
    if a.cmd == "migrate":
        from saw.config import get_settings
        from saw.storage.db import load_models, make_engine
        from saw.storage.migrate import current, head, upgrade

        load_models()
        eng = make_engine(get_settings().database_url)
        before = current(eng)
        after = upgrade(eng)
        print(f"schema: {before or 'none'} -> {after} (head {head()})")
        return 0
    if a.cmd == "make-cert":
        return make_cert(a)
    container.build()
    if a.cmd == "create-user":
        if a.if_missing:
            from sqlalchemy import select

            from saw.storage.models import User

            with session_scope() as s:
                if s.execute(select(User.id).where(User.username == a.username)).first():
                    print(f"user {a.username} already exists - unchanged")
                    return 0
        if a.password_file:
            from pathlib import Path

            pw = Path(a.password_file).read_text(encoding="utf-8").strip()
        else:
            pw = a.password or getpass.getpass("password: ")
        with session_scope() as s:
            u = identity.create_user(s, a.username, pw, a.role, a.display_name)
            print(f"created {u.username} ({u.id}) roles={u.roles}")
    elif a.cmd == "reset-mfa":
        from sqlalchemy import select

        from saw.storage.models import User

        with session_scope() as s:
            u = s.execute(select(User).where(User.username == a.username)).scalar_one_or_none()
            if u is None:
                print(f"no such user: {a.username}")
                return 1
            identity.reset_mfa(s, None, u.id)
            print(f"MFA reset for {a.username}: QR enrollment will be shown at next login")
    elif a.cmd == "set-password":
        from sqlalchemy import select

        from saw.storage.models import User

        pw = getpass.getpass("new password: ")
        if pw != getpass.getpass("repeat: "):
            print("passwords do not match")
            return 1
        with session_scope() as s:
            u = s.execute(select(User).where(User.username == a.username)).scalar_one_or_none()
            if u is None:
                print(f"no such user: {a.username}")
                return 1
            identity.admin_set_password(s, None, u.id, pw)
            print(f"password set for {a.username}; their sessions were revoked")
    elif a.cmd == "verify-audit":
        with session_scope() as s:
            r = audit.verify(s)
            print(f"audit chain OK ({r['entries']} entries)" if r["ok"] else
                  f"audit chain BROKEN ({r['reason']}) at id={r['first_broken_id']}")
            return 0 if r["ok"] else 2
    return 0


def make_cert(a: argparse.Namespace) -> int:
    import datetime as dt
    import ipaddress
    from pathlib import Path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    sans: list[x509.GeneralName] = []
    for n in a.name:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.name[0]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAW")])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=a.days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    (out / "saw.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    (out / "saw.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"wrote {out / 'saw.crt'} and {out / 'saw.key'} (SAN: {', '.join(a.name)}; valid {a.days} days)")
    print("restrict the key file to the service account, and distribute saw.crt to analyst PCs' trusted roots")
    return 0


def serve(a: argparse.Namespace) -> int:
    """One process on purpose: the in-process job runner and SQLite/local stores assume a single worker (ADR-0016)."""
    import uvicorn

    from saw.config import get_settings

    st = get_settings()
    if (a.cert or a.key) and not (a.cert and a.key):
        print("--cert and --key must be given together")
        return 2
    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.cert:
        print("refusing to listen on a network interface without TLS (--cert/--key)")
        return 2
    if a.cert and not st.cookie_secure:
        print("warning: SAW_COOKIE_SECURE is false - set it to true when serving HTTPS")
    uvicorn.run("saw.apps.api.main:app", host=a.host, port=a.port, workers=1, ssl_certfile=a.cert, ssl_keyfile=a.key,
                proxy_headers=False, server_header=False, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
