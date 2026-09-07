"""Cross-honeypot session correlation engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from canary.attack.matrix import technique_info
from canary.core.config import CorrelationConfig
from canary.core.models import AttackerState, NormalizedEvent
from canary.correlate.fingerprint import fingerprint_event
from canary.correlate.score import score_event

if TYPE_CHECKING:
    from canary.core.db import Database


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class CorrelationEngine:
    """Correlates normalized events into per-attacker threat states."""

    def __init__(self, db: Database, config: CorrelationConfig | None = None) -> None:
        self.db = db
        self.config = config or CorrelationConfig()

    async def process(self, event: NormalizedEvent) -> AttackerState | None:
        """Persist an event, update the attacker state, return the new state."""
        key = self._correlation_key(event)
        if key is None:
            return None

        existing = await self.db.get_attacker(key) or {}
        state = AttackerState(**existing) if existing else AttackerState(key=key)

        self._merge_event(state, event)
        await self.db.upsert_attacker(state.model_dump())
        return state

    def _correlation_key(self, event: NormalizedEvent) -> str | None:
        """Best-effort identity key: src_ip (canonical)."""
        return event.src_ip

    def _merge_event(self, state: AttackerState, event: NormalizedEvent) -> None:
        # timestamps
        now = event.timestamp or _now_iso()
        if not state.first_seen:
            state.first_seen = now
        state.last_seen = now

        state.event_count += 1

        # unique-ish list helpers
        state.src_ips = _append_unique(state.src_ips, event.src_ip)
        state.sessions = _append_unique(state.sessions, event.session_id)
        state.honeypots_hit = _append_unique(state.honeypots_hit, event.honeypot)
        state.protocols = _append_unique(state.protocols, event.protocol)

        if event.username:
            state.usernames = _append_unique(state.usernames, event.username)
        if event.password:
            state.passwords = _append_unique(state.passwords, event.password)

        if event.event_type == "auth":
            state.auth_failures += 1

        # ATT&CK technique
        info = technique_info(event.technique)
        if info:
            state.techniques = _append_unique(state.techniques, info["id"])
            state.tactics = _append_unique(state.tactics, info["tactic"])

        # tooling fingerprint (from enriched tool field set at ingest time)
        tool = event.tool
        if not tool:
            tool = fingerprint_event(event)
        if tool:
            state.tools = _append_unique(state.tools, tool)

        # scoring
        if event.event_type == "command":
            state.command_count += 1
        delta = score_event(
            event_type=event.event_type,
            technique_detected=bool(event.technique),
            new_honeypot=len(state.honeypots_hit) > 1,
            protocol_present=bool(event.protocol),
            tool_detected=bool(tool),
            config=self.config,
        )
        state.score += delta


def _append_unique(items: list[Any], value: Any) -> list[Any]:
    if not value:
        return items
    value = str(value)
    if value not in items:
        items.append(value)
    return items
