"""Hybrid Similar Case search (docs/26, ADR-0008): S = 0.45·Feature + 0.35·Vector + 0.20·Keyword.

Local mode: deterministic hashed n-gram embedding (EmbeddingPort fallback) + in-process BM25 with Korean char-bigrams.
Production: bge-m3/multilingual-e5 embeddings in pgvector and nori keyword search in OpenSearch (ENV-09, ENV-02, ENV-03).
Scores are always decomposed; LLMs are never used to compute similarity.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime
from typing import Protocol

from sqlalchemy import JSON, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from saw.knowledge.features import compare, from_findings
from saw.storage.db import Base, new_id, session_scope, utcnow

WEIGHTS = {"feature": 0.45, "vector": 0.35, "keyword": 0.20}
DIM = 512


class KnowledgeDoc(Base):
    __tablename__ = "kn_doc"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    ref_type: Mapped[str] = mapped_column(String(16), index=True)  # experience | investigation | case
    ref_id: Mapped[str] = mapped_column(String(36), index=True)
    display_id: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(256))
    verdict: Mapped[str | None] = mapped_column(String(24), nullable=True)
    card: Mapped[str] = mapped_column(Text)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    vector: Mapped[list] = mapped_column(JSON, default=list)
    model: Mapped[str] = mapped_column(String(64))
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    dim: Mapped[int] = mapped_column(Integer, default=DIM)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EmbeddingPort(Protocol):
    name: str

    def embed(self, text: str) -> list[float]: ...


class HashEmbedding:
    """Deterministic hashing-trick embedding over word + char-3gram features (local fallback, ENV-09)."""

    name = "hash-ngram-512"

    def embed(self, text: str) -> list[float]:
        v = [0.0] * DIM
        for tok in tokens(text):
            h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
            v[h % DIM] += 1.0 if (h >> 63) & 1 else -1.0
        n = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / n for x in v]


def tokens(text: str) -> list[str]:
    t = text.lower()
    words = re.findall(r"[a-z0-9_<>./:-]{2,}", t)
    out = list(words)
    for w in words:
        out += [w[i:i + 3] for i in range(max(0, len(w) - 2))]
    for run in re.findall(r"[가-힣]+", t):  # Korean: char bigrams (nori in production)
        out += [run[i:i + 2] for i in range(max(1, len(run) - 1))]
    return out


_embedder: EmbeddingPort = HashEmbedding()


def card_text(title: str, features: dict, extra: str = "") -> str:
    """Structured 'Case Card' (no raw logs) used for embedding (docs/26 §3)."""
    parts = [f"title: {title}"]
    for k, v in sorted(features.items()):
        if k.startswith("_"):
            continue
        parts.append(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
    if extra:
        parts.append(extra[:1000])
    return "; ".join(parts)


def _upsert(s: Session, ref_type: str, ref_id: str, display_id: str, title: str, verdict: str | None, features: dict,
            extra_text: str = "", extra: dict | None = None) -> KnowledgeDoc:
    card = card_text(title, features, extra_text)
    d = s.execute(select(KnowledgeDoc).where(KnowledgeDoc.ref_type == ref_type, KnowledgeDoc.ref_id == ref_id)).scalar_one_or_none()
    if d is None:
        d = KnowledgeDoc(ref_type=ref_type, ref_id=ref_id, display_id=display_id, title=title, card=card, model=_embedder.name)
        s.add(d)
    d.title, d.verdict, d.card, d.features, d.extra = title, verdict, card, features, extra or {}
    d.vector, d.model, d.updated_at = _embedder.embed(card), _embedder.name, utcnow()
    return d


def index_experience(e, s: Session | None = None) -> None:
    """Index the approved copy. Pass the caller's session to avoid a second SQLite writer in the same thread."""
    if not e.approved_data:
        return
    if s is None:
        with session_scope() as s2:
            return index_experience(e, s2)
    a = e.approved_data
    if True:
        _upsert(s, "experience", e.id, e.display_id, a.get("title", ""), a.get("final_verdict"), a.get("behavior_features") or {},
                f"{a.get('reason', '')} {a.get('response', '')}",
                {"recommended_checks": [c.get("check") for c in a.get("recommended_checks") or []],
                 "fp_conditions": [str(c) for c in a.get("false_positive_conditions") or []],
                 "category": a.get("category"), "created": e.created_at.isoformat() if e.created_at else None})


def index_investigation(s: Session, inv) -> KnowledgeDoc | None:
    from saw.core.application.analysis import finding_dict
    from saw.storage.models import Finding

    fs = [finding_dict(f) for f in s.execute(select(Finding).where(Finding.investigation_id == inv.id)
                                             .order_by(Finding.risk_score.desc())).scalars()]
    if not fs:
        return None
    return _upsert(s, "investigation", inv.id, inv.display_id, inv.title, inv.verdict, from_findings(fs[:10]),
                   inv.verdict_reason or "", {"closed_at": inv.closed_at.isoformat() if inv.closed_at else None})


def _bm25(query: list[str], docs: list[list[str]], k1: float = 1.2, b: float = 0.75) -> list[float]:
    n = len(docs)
    avg = sum(len(d) for d in docs) / max(1, n)
    df = Counter(t for d in docs for t in set(d))
    out = []
    qset = set(query)
    for d in docs:
        tf = Counter(d)
        sc = 0.0
        for t in qset:
            if t in tf:
                idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
                sc += idf * tf[t] * (k1 + 1) / (tf[t] + k1 * (1 - b + b * len(d) / max(1, avg)))
        out.append(sc)
    mx = max(out) if out else 0
    return [x / mx if mx else 0.0 for x in out]


def search(s: Session, features: dict, text: str, k: int = 10, exclude_ref: str | None = None,
           types: tuple[str, ...] = ("experience", "investigation"),
           allowed_ref_ids: frozenset[str] | None = None) -> list[dict]:
    q = select(KnowledgeDoc).where(KnowledgeDoc.ref_type.in_(types))
    if allowed_ref_ids is not None:
        q = q.where(KnowledgeDoc.ref_id.in_(allowed_ref_ids))
    docs = [d for d in s.execute(q).scalars()
            if d.ref_id != exclude_ref]
    if not docs:
        return []
    qcard = card_text(text, features)
    qv = _embedder.embed(qcard)
    kw = _bm25(tokens(qcard), [tokens(d.card) for d in docs])
    out = []
    for d, ks in zip(docs, kw, strict=True):
        fs, same, diff = compare(features, d.features or {})
        vs = max(0.0, sum(a * b for a, b in zip(qv, d.vector, strict=False))) if d.model == _embedder.name else 0.0
        score = WEIGHTS["feature"] * fs + WEIGHTS["vector"] * vs + WEIGHTS["keyword"] * ks
        out.append({"ref_type": d.ref_type, "ref_id": d.ref_id, "display_id": d.display_id, "title": d.title,
                    "verdict": d.verdict, "score": round(score, 3),
                    "breakdown": {"feature": round(fs, 2), "vector": round(vs, 2), "keyword": round(ks, 2)},
                    "same": same, "different": diff, "extra": d.extra, "model": d.model})
    out.sort(key=lambda x: -x["score"])
    return out[:k]


def features_for_investigation(s: Session, inv_id: str, finding_id: str | None = None) -> tuple[dict, str]:
    from saw.core.application.analysis import finding_dict
    from saw.storage.models import Finding, Investigation

    q = select(Finding).where(Finding.investigation_id == inv_id)
    if finding_id:
        q = q.where(Finding.id == finding_id)
    fs = [finding_dict(f) for f in s.execute(q.order_by(Finding.risk_score.desc())).scalars()][:10]
    inv = s.get(Investigation, inv_id)
    text = (inv.title if inv else "") + " " + " ".join(f["title"] for f in fs[:5])
    return from_findings(fs), text


def rebuild(s: Session) -> int:
    from saw.knowledge.models import Experience
    from saw.storage.models import Investigation

    n = 0
    for e in s.execute(select(Experience).where(Experience.approved_data.isnot(None))).scalars():
        index_experience(e, s)
        n += 1
    for inv in s.execute(select(Investigation).where(Investigation.verdict.isnot(None))).scalars():
        if index_investigation(s, inv):
            n += 1
    return n
