"""Read-only installer verification must distinguish stopped from healthy."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest


def module():
    from saw.devtools import install_verify
    return install_verify


def make_install(tmp_path, *, expired=False):
    root=tmp_path/"SAW test"
    for sub in ("app","tls","data/saw","data/objects","data/opensearch","opensearch-2.19.6/config","secrets"):
        (root/sub).mkdir(parents=True,exist_ok=True)
    (root/"app/.env").write_text(
        f"SAW_DATABASE_URL=postgresql+psycopg://saw:synthetic-password@127.0.0.1:55450/saw\n"
        f"SAW_DATA_DIR={root/'data/saw'}\nSAW_OBJECT_STORE_ROOT={root/'data/objects'}\n"
        "SAW_EVENT_STORE=opensearch\nSAW_OBJECT_STORE=local\nSAW_SCHEMA_MODE=migrate\n"
        "SAW_COOKIE_SECURE=true\nSAW_OPENSEARCH_URL=http://127.0.0.1:59250\n",
        encoding="utf-8")
    (root/"opensearch-2.19.6/config/opensearch.yml").write_text(
        "path.data: " + json.dumps(str(root/"data/opensearch"))+"\n",encoding="utf-8")
    (root/"secrets/postgres-superuser.pw").write_text("synthetic-super",encoding="ascii")
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"saw.invalid")])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
          .not_valid_after(now-timedelta(days=1) if expired else now+timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("saw.invalid")]),critical=False)
          .sign(key,hashes.SHA256()))
    (root/"tls/saw.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/"tls/saw.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return root


def test_stopped_valid_install_is_not_claimed_live_or_modified(tmp_path,monkeypatch):
    m=module(); root=make_install(tmp_path)
    before={p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}
    monkeypatch.setattr(m,"_listening",lambda port:False)
    result=m.verify(root,"saw.invalid",58450,55450,59250,"0014")
    assert result["ok"] and not result["ready"]
    assert result["checks"]["database"]["status"]=="NOT_RUN"
    assert result["checks"]["api"]["status"]=="NOT_RUN"
    assert result["checks"]["tls"]["status"]=="PASS"
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob("*") if p.is_file()}==before


@pytest.mark.parametrize("problem",["expired","wrong_host","wrong_key","outside_data"])
def test_static_invalid_install_fails_without_printing_secrets(tmp_path,monkeypatch,problem):
    m=module(); root=make_install(tmp_path,expired=problem=="expired")
    host="other.invalid" if problem=="wrong_host" else "saw.invalid"
    if problem=="wrong_key":
        foreign=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        (root/"tls/saw.key").write_bytes(foreign.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    if problem=="outside_data":
        env=root/"app/.env"
        env.write_text(env.read_text().replace(str(root/"data/saw"),str(tmp_path/"outside")),encoding="utf-8")
    monkeypatch.setattr(m,"_listening",lambda port:False)
    result=m.verify(root,host,58450,55450,59250,"0014")
    assert not result["ok"]
    assert "synthetic-password" not in json.dumps(result)
    assert "PRIVATE KEY" not in json.dumps(result)


def test_require_live_and_partially_running_install_fail(tmp_path,monkeypatch):
    m=module(); root=make_install(tmp_path)
    monkeypatch.setattr(m,"_listening",lambda port:False)
    assert not m.verify(root,"saw.invalid",58450,55450,59250,"0014",require_live=True)["ok"]
    monkeypatch.setattr(m,"_listening",lambda port:port==58450)
    monkeypatch.setattr(m,"_runtime_check",lambda *args,**kwargs:True)
    assert not m.verify(root,"saw.invalid",58450,55450,59250,"0014")["ok"]


def test_database_verification_is_readonly_and_requires_schema_admin(monkeypatch):
    m=module(); calls=[]
    class Connection:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def execute(self,sql):
            calls.append(sql)
            class Rows:
                def fetchall(self):
                    return [("C:/synthetic/data/postgresql".encode("ascii").hex(),)] if "data_directory" in sql else ([("0014",)] if "alembic" in sql else [(1,)])
            return Rows()
    def connect(**kwargs):
        assert kwargs["host"]=="127.0.0.1"
        assert kwargs["client_encoding"]=="UTF8"
        assert "default_transaction_read_only=on" in kwargs["options"]
        return Connection()
    monkeypatch.setattr(m.psycopg,"connect",connect)
    assert m._database({"user":"saw","password":"synthetic-password","port":55450,"dbname":"saw"},"0014",Path("C:/synthetic/data/postgresql"),"synthetic-super")
    assert len(calls)==3 and all(sql.lstrip().upper().startswith("SELECT ") for sql in calls)
    assert not m._database({"user":"saw","password":"synthetic-password","port":55450,"dbname":"saw"},"9999",Path("C:/synthetic/data/postgresql"),"synthetic-super")


def test_database_wrong_data_directory_is_rejected_before_app_query(monkeypatch):
    m=module(); calls=[]
    class Connection:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def execute(self,sql):
            calls.append(sql)
            class Rows:
                def fetchall(self): return [("C:/different/data".encode("ascii").hex(),)]
            return Rows()
    monkeypatch.setattr(m.psycopg,"connect",lambda **kwargs:Connection())
    assert not m._database({"user":"saw","password":"synthetic","port":55450,"dbname":"saw"},"0014",Path("C:/expected/data"),"synthetic")
    assert len(calls)==1 and "data_directory" in calls[0]


def test_native_directory_path_decodes_windows_bytes_without_loss(monkeypatch):
    m=module()
    monkeypatch.setattr(m,"_windows_path_encoding",lambda:"cp949",raising=False)
    expected="D:/관제 SAW/data/postgresql"
    assert m._native_data_path(expected.encode("cp949").hex())==expected
    for invalid in ("invalid-hex", "81", ""):
        with pytest.raises((ValueError,UnicodeDecodeError)):
            m._native_data_path(invalid)
