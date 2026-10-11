"""Runtime configuration (12-factor, env prefix SAW_)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]
VAR = ROOT / "var"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SAW_", env_file=str(ROOT / ".env"), env_file_encoding="utf-8-sig",
                                      extra="ignore")

    env: str = "dev"
    data_dir: Path = VAR

    # Storage backends: local fallbacks by default, infra adapters selectable (see ENV-VERIFICATION.md)
    database_url: str = f"sqlite:///{(VAR / 'saw.db').as_posix()}"
    schema_mode: str = "create_all"  # create_all (dev/tests) | migrate (production: Alembic upgrade head at start)
    event_store: str = "sqlite"  # sqlite | opensearch
    event_store_path: str = str(VAR / "events.db")
    opensearch_url: str = "http://127.0.0.1:9200"  # Windows profile: loopback-only node (ADR-0016)
    opensearch_user: str = ""
    opensearch_password: str = ""
    opensearch_verify_certs: bool = True
    opensearch_ca_certs: str = ""
    opensearch_index_prefix: str = "saw"
    # request: a batch is on disk before it is acknowledged (shared server). async: synced every 10 s (single analyst PC
    # with a slow disk; a crash can lose the last seconds, which the one user re-ingests).
    opensearch_durability: str = "request"
    object_store: str = "local"  # local | s3
    object_store_root: str = str(VAR / "objects")
    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: str = ""
    s3_secret_key: str = ""
    job_runner: str = "inprocess"  # inprocess | celery
    broker_url: str = "redis://localhost:6379/0"
    # Small analyst PCs: one heavy job at a time keeps the UI responsive next to OpenSearch's JVM
    job_workers: int = 1
    # auto = structured events (web/network/NDR) are stored without raw_event, read back from the evidence file
    # on demand (about half the index size); all = keep every raw line in the index (full-text search on raw)
    raw_store: str = "auto"

    # PCAP tools (optional; empty = search PATH). Without Zeek the built-in analyzer is used (ADR-0016).
    zeek_path: str = ""
    suricata_path: str = ""  # e.g. C:\Program Files\Suricata\suricata.exe
    suricata_config: str = ""
    suricata_rules: str = ""  # offline rules file (air-gapped: imported ET Open bundle)
    tshark_path: str = ""
    capinfos_path: str = ""

    # Web UI build served by the API in production (empty/missing → API only; dev uses the Vite server)
    web_dist: str = str(ROOT / "apps" / "web" / "dist")

    # Security
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_secure: bool = False  # True in production (TLS)
    mfa_required: bool = True
    login_max_failures: int = 5
    login_lock_minutes: int = 15

    # Limits
    sync_input_max_bytes: int = 5 * 1024 * 1024
    upload_part_max_bytes: int = 64 * 1024 * 1024
    upload_file_max_bytes: int = 20 * 1024 * 1024 * 1024
    decompress_max_ratio: int = 200
    decompress_max_depth: int = 3
    decompress_max_entries: int = 10_000
    decompress_max_total_bytes: int = 500 * 1024 * 1024 * 1024

    default_timezone: str = "Asia/Seoul"

    # SOC Assistant (docs/29). template = offline deterministic renderer (not an LLM); ollama/openai_compat = ENV-08
    llm_provider: str = "template"  # none | template | ollama | openai_compat
    llm_url: str = "http://127.0.0.1:11434"
    llm_model: str = "qwen2.5:14b-instruct"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    return s
