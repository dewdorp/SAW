"""The durable requester rotation cursor; SQL Jobs remain the backlog."""
from __future__ import annotations

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from saw.storage.db import Base


class QueueCursor(Base):
    __tablename__ = "an_job_queue_cursor"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_requester: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
