"""STIX 2.1 bundle generator for Canary IOCs."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from canary.core.models import AttackerState, NormalizedEvent

IP_CACHE: set[str] = set()
FILE_CACHE: set[str] = set()


def _uid(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid5(uuid.NAMESPACE_OID, str(uuid.uuid4()))}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _extract_url_paths(events: list[NormalizedEvent]) -> set[str]:
    paths: set[str] = set()
    for event in events:
        if event.url:
            parsed = urlparse(event.url)
            if parsed.scheme in ("http", "https") and parsed.path:
                paths.add(parsed.path)
    return paths


def build_bundle(
    attackers: list[AttackerState],
    events: list[NormalizedEvent] | None = None,
) -> dict[str, Any]:
    """Generate a STIX 2.1 bundle of observable indicators from attacker states."""
    objects: list[dict[str, Any]] = []
    now = _now()
    IP_CACHE.clear()
    FILE_CACHE.clear()

    for attacker in attackers:
        src_ips = [ip for ip in (attacker.src_ips or [attacker.key]) if ip]
        for ip in src_ips:
            if ip in IP_CACHE:
                continue
            IP_CACHE.add(ip)

            indicator_id = _uid("indicator")
            ip_id = _uid("ipv4-addr")

            indicator: dict[str, Any] = {
                "type": "indicator",
                "id": indicator_id,
                "created": now,
                "modified": now,
                "name": f"Canary: attacker {ip}",
                "indicator_types": ["malicious-activity"],
                "pattern_type": "stix",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "valid_from": now,
                "labels": ["honeypot", "observed"],
                "description": _describe_attacker(attacker),
            }
            objects.append(indicator)
            objects.append({"type": "ipv4-addr", "id": ip_id, "value": ip})
            objects.append(
                {
                    "type": "relationship",
                    "id": _uid("relationship"),
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": ip_id,
                }
            )

    if events:
        for path in _extract_url_paths(events):
            if path in FILE_CACHE or not path.strip("/"):
                continue
            FILE_CACHE.add(path)
            objects.append(
                {
                    "type": "file",
                    "id": _uid("file"),
                    "name": path.rsplit("/", 1)[-1],
                    "labels": ["url-path", "observed"],
                }
            )

    return {"type": "bundle", "id": _uid("bundle"), "spec_version": "2.1", "objects": objects}


def _describe_attacker(attacker: AttackerState) -> str:
    bits = [
        f"{attacker.event_count} events",
        "honeypots: " + ",".join(attacker.honeypots_hit or ["unknown"]),
        "techniques: " + ",".join(attacker.techniques or ["unknown"]),
        f"score {attacker.score}",
    ]
    return "; ".join(bits)
