"""End-to-end ingestion pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

from canary.attack.rules import detect_techniques
from canary.correlate.engine import CorrelationEngine
from canary.correlate.fingerprint import fingerprint_event
from canary.ingest.normalizer import normalize_raw

if TYPE_CHECKING:
    from canary.core.db import Database
    from canary.core.models import NormalizedEvent


class Pipeline:
    """Wires ingestion → ATT&CK mapping → correlation → persistence."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.engine = CorrelationEngine(db)

    async def ingest(self, raw: dict) -> NormalizedEvent | None:
        event = normalize_raw(raw)
        technique, tactic, confidence = detect_techniques(event)
        event.technique = technique
        event.tactic = tactic
        event.confidence = confidence
        tool = fingerprint_event(event)
        if tool:
            event.tool = tool

        event_id = await self.db.add_event(event.model_dump(exclude_none=True))
        event.id = event_id
        await self.engine.process(event)
        return event
