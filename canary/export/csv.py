"""CSV export of attacker states."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from canary.core.models import AttackerState


def attacker_csv(attackers: Iterable[AttackerState]) -> list[dict[str, Any]]:
    """Flatten attacker states into CSV-ready rows."""
    rows: list[dict[str, Any]] = []
    for a in attackers:
        rows.append(
            {
                "key": a.key,
                "src_ips": "|".join(a.src_ips or []),
                "event_count": a.event_count,
                "score": a.score,
                "auth_failures": a.auth_failures,
                "command_count": a.command_count,
                "honeypots_hit": "|".join(a.honeypots_hit or []),
                "protocols": "|".join(a.protocols or []),
                "techniques": "|".join(a.techniques or []),
                "tactics": "|".join(a.tactics or []),
                "tools": "|".join(a.tools or []),
                "first_seen": a.first_seen or "",
                "last_seen": a.last_seen or "",
            }
        )
    return rows


def write_csv(rows: list[dict[str, Any]], output_path: str) -> None:
    if not rows:
        return
    with Path(output_path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
