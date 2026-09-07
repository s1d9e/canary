"""Event normalization for multiple honeypot log formats."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from canary.core.errors import NormalizationError
from canary.core.models import IngestEvent, NormalizedEvent

# Honeypot-specific fields that map into the canonical schema
_COWRIE_TYPE_MAP = {
    "login": "auth",
    "command": "command",
    "connection": "connection",
    "download": "download",
    "file": "file",
    "unknown": "generic",
}


def _cowrie_type(payload: dict[str, Any]) -> str:
    """Map a Cowrie eventid (or legacy type) to a canonical Canary event type."""
    eventid = str(payload.get("eventid") or payload.get("type") or "unknown")
    if "login" in eventid:
        return "auth"
    if "command" in eventid or eventid == "command":
        return "command"
    if "download" in eventid or "upload" in eventid:
        return "download"
    if "file" in eventid or "tarball" in eventid:
        return "file"
    if "connect" in eventid or eventid == "connection":
        return "connection"
    return "generic"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _coerce_ip(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value)


def normalize_raw(payload: dict[str, Any]) -> NormalizedEvent:
    """Normalize an incoming payload into the canonical event schema.

    Accepts both the raw JSON body posted to the ingestion API and already-
    canonical `IngestEvent`-shaped payloads. Known honeypot formats
    (cowrie, blood-web, voltron-ssh, backrooms, dionaea) are auto-detected.
    """
    source = payload.get("honeypot", "").lower()
    if isinstance(payload.get("data"), dict) and "src_ip" not in payload:
        nester = payload["data"]
        merged = dict(payload)
        for k, v in nester.items():
            merged.setdefault(k, v)
        payload = merged

    if not source:
        eventid = str(payload.get("eventid", ""))
        if (
            eventid.startswith("cowrie")
            or payload.get("session")
            or (
                payload.get("type") in ("login", "command", "connection", "download")
                and "message" in payload
            )
        ):
            source = "cowrie"

    # ---- Cowrie JSON log format (HPFEEDS) ----
    if source == "cowrie":
        ev_type = _cowrie_type(payload)
        norm = NormalizedEvent(
            honeypot="cowrie",
            event_type=ev_type,
            session_id=str(payload.get("session") or ""),
            src_ip=_coerce_ip(
                payload.get("src_ip") or payload.get("src_host") or payload.get("peer")
            ),
            src_port=int(payload["src_port"]) if payload.get("src_port") is not None else None,
            dst_ip=_coerce_ip(payload.get("dst_ip") or payload.get("dst_host")),
            dst_port=int(payload["dst_port"]) if payload.get("dst_port") is not None else None,
            timestamp=_now_iso(),
            raw=json.dumps(payload, ensure_ascii=False)[:4000],
            technique=None,
            tactic=None,
            tool=None,
            confidence=0.0,
        )
        msg = payload.get("message")
        if ev_type == "auth":
            norm.username = str(payload.get("username") or "")
            norm.password = str(payload.get("password") or "")
        elif ev_type == "command":
            norm.command = str(payload.get("input") or msg or "")
            norm.username = str(payload.get("username") or "")
        elif ev_type == "connection":
            protocol = str(payload.get("protocol") or "")
            if not protocol and msg:
                protocol = str(msg).replace("-", "").lower()
            norm.protocol = protocol or None
        elif ev_type == "download":
            norm.url = str(payload.get("url") or "")
            norm.command = str(payload.get("shasum") or msg or "")[:400]
        norm.timestamp = str(payload.get("timestamp") or norm.timestamp)
        return norm

    # ---- Canonical generate (blood-web, voltron-ssh, backrooms, custom) ----
    try:
        event = IngestEvent.model_validate(payload)
    except Exception as exc:
        raise NormalizationError(f"Invalid event payload: {exc}") from exc

    event_type = (event.event_type or "generic").lower()
    technique, tactic, confidence = None, None, None
    # Extract auth events from generic payloads for robustness
    if event_type == "generic" and (event.username or event.password or event.raw):
        low = f"{event.username or ''} {event.password or ''} {event.raw or ''}".lower()
        if "login" in low or "auth" in low or event.password:
            event_type = "auth"

    command = event.command
    return NormalizedEvent(
        honeypot=event.honeypot.lower(),
        event_type=event_type,
        protocol=(event.protocol or "").lower() if event.protocol else None,
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        session_id=event.session_id,
        timestamp=event.timestamp or _now_iso(),
        username=event.username,
        password=event.password,
        command=command,
        url=event.url,
        method=event.method.upper() if event.method else None,
        user_agent=event.user_agent,
        response_code=event.response_code,
        data=event.data or {},
        raw=event.raw,
        technique=technique,  # filled later by correlator
        tactic=tactic,
        tool=None,
        confidence=confidence or 0.0,
    )
