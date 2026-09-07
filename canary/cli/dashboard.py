"""Interactive Rich TUI dashboard for Canary."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from canary.core.db import Database


def _build_table(attackers: list[dict], title: str, refresh: timedelta) -> Group:
    header = Text("Canary — live honeypot intelligence", style="bold green")
    sub = Text(
        f"  refreshes every {int(refresh.total_seconds())}s · {len(attackers)} attacker(s)",
        style="dim",
    )
    table = Table(title=title, header_style="bold", expand=True)
    table.add_column("Attacker", style="cyan")
    table.add_column("Honeypots", style="magenta")
    table.add_column("Techniques", style="blue")
    table.add_column("Tools", style="red")
    table.add_column("Score", justify="right", style="bold green")
    table.add_column("Events", justify="right")
    table.add_column("Last seen", style="dim")

    for a in attackers[:40]:
        techniques = ",".join(a.get("techniques", []) or ["-"])
        table.add_row(
            str(a.get("key", "?")),
            ",".join(a.get("honeypots_hit", []) or ["-"]),
            techniques,
            ",".join(a.get("tools", []) or ["-"]),
            str(a["score"]),
            str(a.get("event_count", 0)),
            str(a.get("last_seen", "-")),
        )
    return Group(header, sub, table)


async def _samples(db: Database) -> list[dict]:
    return await db.list_attackers(limit=40)


def run_tui(db: Database, refresh: float | None = None) -> None:
    """Blocking loop rendering the live dashboard."""
    if refresh is None:
        refresh = 5.0
    interval = timedelta(seconds=refresh)

    with Live(console=None, refresh_per_second=1 / max(refresh, 0.5), transient=True) as live:
        try:
            while True:
                attackers = asyncio.run(_samples(db))
                live.update(_build_table(attackers, "Top attackers by risk score", interval))
                asyncio.run(_wait_event(interval.total_seconds()))
        except KeyboardInterrupt:
            pass


async def _wait_event(seconds: float) -> None:
    await asyncio.sleep(seconds)
