"""Async SQLAlchemy + SQLite persistence layer for Canary."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import (
    Float,
    Integer,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from canary.core.errors import DatabaseError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    honeypot: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(256), nullable=True)
    password: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data: Mapped[str] = mapped_column(Text, default="{}")
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    technique: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    recorded_at: Mapped[str | None] = mapped_column(String(64), default=None)


class AttackerRecord(Base):
    __tablename__ = "attackers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), index=True, unique=True)
    src_ips: Mapped[str] = mapped_column(Text, default="[]")
    sessions: Mapped[str] = mapped_column(Text, default="[]")
    honeypots_hit: Mapped[str] = mapped_column(Text, default="[]")
    protocols: Mapped[str] = mapped_column(Text, default="[]")
    techniques: Mapped[str] = mapped_column(Text, default="[]")
    tactics: Mapped[str] = mapped_column(Text, default="[]")
    tools: Mapped[str] = mapped_column(Text, default="[]")
    usernames: Mapped[str] = mapped_column(Text, default="[]")
    passwords: Mapped[str] = mapped_column(Text, default="[]")
    first_seen: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(64), default=None)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    auth_failures: Mapped[int] = mapped_column(Integer, default=0)
    command_count: Mapped[int] = mapped_column(Integer, default=0)
    score: Mapped[int] = mapped_column(Integer, default=0)


class Database:
    """Async SQLite store backed by SQLAlchemy."""

    def __init__(self, path: str = "canary.db", echo: bool = False) -> None:
        self.path = str(Path(path).expanduser())
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None
        self.echo = echo

    async def connect(self) -> None:
        url = f"sqlite+aiosqlite:///{self.path}"
        self._engine = create_async_engine(url, echo=self.echo)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def disconnect(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None

    def _require(self) -> async_sessionmaker[AsyncSession]:
        if self._sessionmaker is None:
            raise DatabaseError("Database not connected. Call connect() first.")
        return self._sessionmaker

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        sm = self._require()
        async with sm() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    async def add_event(self, event: dict) -> int:
        import json

        payload = {k: v for k, v in event.items() if k != "id"}
        if isinstance(payload.get("data"), (dict, list)):
            payload["data"] = json.dumps(payload["data"])
        payload.setdefault("recorded_at", None)
        record = EventRecord(**payload)
        async with self.session() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return int(record.id)

    async def upsert_attacker(self, state: dict) -> None:
        keys_int = [  # JSON-stringify list fields for storage
            "src_ips",
            "sessions",
            "honeypots_hit",
            "protocols",
            "techniques",
            "tactics",
            "tools",
            "usernames",
            "passwords",
        ]
        record = AttackerRecord(key=state["key"])
        import json

        for field in keys_int:
            val = state.get(field, [])
            setattr(record, field, json.dumps(val) if isinstance(val, list) else str(val))
        for field in (
            "first_seen",
            "last_seen",
            "event_count",
            "auth_failures",
            "command_count",
            "score",
        ):
            setattr(record, field, state.get(field))
        async with self.session() as session:
            existing = await session.execute(
                select(AttackerRecord).where(AttackerRecord.key == state["key"])
            )
            row = existing.scalar_one_or_none()
            if row is None:
                session.add(record)
            else:
                for field in keys_int:
                    setattr(row, field, getattr(record, field))
                for field in (
                    "first_seen",
                    "last_seen",
                    "event_count",
                    "auth_failures",
                    "command_count",
                    "score",
                ):
                    setattr(row, field, getattr(record, field))
            await session.commit()

    async def get_attacker(self, key: str) -> dict | None:
        async with self.session() as session:
            row = (
                await session.execute(select(AttackerRecord).where(AttackerRecord.key == key))
            ).scalar_one_or_none()
        if row is None:
            return None
        return self._attacker_to_dict(row)

    async def list_attackers(self, limit: int = 50) -> list[dict]:
        async with self.session() as session:
            rows = (
                (
                    await session.execute(
                        select(AttackerRecord).order_by(AttackerRecord.score.desc()).limit(limit)
                    )
                )
                .scalars()
                .all()
            )
        return [self._attacker_to_dict(r) for r in rows]

    async def event_count(self) -> int:
        async with self.session() as session:
            val = (
                await session.execute(select(func.count()).select_from(EventRecord))
            ).scalar_one()
        return int(val)

    async def list_events(self, limit: int = 200) -> list[dict]:
        """Return the most recent events as packet-list-friendly dicts."""
        import json

        async with self.session() as session:
            rows = (
                (
                    await session.execute(
                        select(EventRecord).order_by(EventRecord.id.desc()).limit(limit)
                    )
                )
                .scalars()
                .all()
            )
        events = []
        for r in rows:
            raw_data = r.data or "{}"
            try:
                data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            except (TypeError, ValueError):
                data = {}
            events.append(
                {
                    "id": r.id,
                    "honeypot": r.honeypot,
                    "event_type": r.event_type,
                    "protocol": r.protocol,
                    "src_ip": r.src_ip,
                    "src_port": r.src_port,
                    "dst_ip": r.dst_ip,
                    "dst_port": r.dst_port,
                    "session_id": r.session_id,
                    "timestamp": r.timestamp,
                    "username": r.username,
                    "password": r.password,
                    "command": r.command,
                    "url": r.url,
                    "method": r.method,
                    "user_agent": r.user_agent,
                    "response_code": r.response_code,
                    "technique": r.technique,
                    "tactic": r.tactic,
                    "tool": r.tool,
                    "confidence": r.confidence,
                    "raw": r.raw,
                    "data": data,
                }
            )
        return events

    async def attacker_count(self) -> int:
        async with self.session() as session:
            val = (
                await session.execute(select(func.count()).select_from(AttackerRecord))
            ).scalar_one()
        return int(val)

    @staticmethod
    def _attacker_to_dict(row: AttackerRecord) -> dict:
        import json

        def _load(raw: str) -> list:
            try:
                return json.loads(raw)
            except (TypeError, ValueError):
                return []

        return {
            "key": row.key,
            "src_ips": _load(row.src_ips),
            "sessions": _load(row.sessions),
            "honeypots_hit": _load(row.honeypots_hit),
            "protocols": _load(row.protocols),
            "techniques": _load(row.techniques),
            "tactics": _load(row.tactics),
            "tools": _load(row.tools),
            "usernames": _load(row.usernames),
            "passwords": _load(row.passwords),
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "event_count": row.event_count,
            "auth_failures": row.auth_failures,
            "command_count": row.command_count,
            "score": row.score,
        }
