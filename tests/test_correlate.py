"""Tests for the correlation engine and scoring."""

from __future__ import annotations

import pytest

from canary.core.db import Database
from canary.core.models import NormalizedEvent
from canary.correlate.engine import CorrelationEngine
from canary.correlate.score import score_event


def _event(src_ip: str = "203.0.113.7", **kw) -> NormalizedEvent:
    base = {
        "honeypot": "voltron-ssh",
        "event_type": "auth",
        "protocol": "ssh",
        "src_ip": src_ip,
        "username": "root",
        "password": "admin123",
        "timestamp": "2026-09-07T00:00:00Z",
    }
    base.update(kw)
    return NormalizedEvent(**base)


@pytest.mark.asyncio
async def test_engine_correlates_across_honeypots(tmp_path) -> None:
    db = Database(path=str(tmp_path / "t.db"))
    await db.connect()
    engine = CorrelationEngine(db)

    await engine.process(
        _event(event_type="auth", raw="login attempt root:admin123", technique="T1110")
    )
    state = await engine.process(
        _event(
            src_ip="203.0.113.7",
            honeypot="blood-web",
            protocol="http",
            event_type="http",
            url="/wp-login?cve-2024-9999",
            user_agent="nuclei v3.2.0",
            raw="scan",
        )
    )

    assert state is not None
    assert state.key == "203.0.113.7"
    assert len(state.honeypots_hit) == 2
    assert "voltron-ssh" in state.honeypots_hit
    assert "blood-web" in state.honeypots_hit
    assert "T1110" in state.techniques
    assert state.auth_failures == 1
    assert state.event_count == 2
    assert state.score > 0
    assert state.tools == ["nuclei"]

    persisted = await db.get_attacker("203.0.113.7")
    assert persisted is not None
    assert persisted["score"] == state.score

    await db.disconnect()


@pytest.mark.asyncio
async def test_distinct_attackers_are_not_merged(tmp_path) -> None:
    db = Database(path=str(tmp_path / "t.db"))
    await db.connect()
    engine = CorrelationEngine(db)
    await engine.process(_event(src_ip="203.0.113.7"))
    await engine.process(_event(src_ip="198.51.100.9"))
    attackers = await db.list_attackers()
    assert len(attackers) == 2
    await db.disconnect()


class TestScoring:
    def test_auth_event(self) -> None:
        assert score_event("auth", technique_detected=True) >= 5

    def test_command_event(self) -> None:
        assert score_event("command", technique_detected=False) >= 8

    def test_technique_boost(self) -> None:
        base = score_event("http", technique_detected=False)
        boosted = score_event("http", technique_detected=True)
        assert boosted > base

    def test_tool_and_protocol_boost(self) -> None:
        plain = score_event("http", technique_detected=False)
        rich = score_event(
            "http", technique_detected=False, tool_detected=True, protocol_present=True
        )
        assert rich > plain
