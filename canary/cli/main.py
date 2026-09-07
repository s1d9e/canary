"""Canary CLI entrypoint (Typer)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from canary import __version__
from canary.attack.matrix import tactic_label, technique_info
from canary.core.config import Config
from canary.core.db import Database
from canary.core.errors import IngestionError
from canary.core.models import AttackerState
from canary.export.csv import attacker_csv, write_csv
from canary.export.stix import build_bundle
from canary.ingest.pipeline import Pipeline

app = typer.Typer(add_completion=False, help="Canary — Honeypot aggregation & threat correlation.")
console = Console()


def _get_db(config: Config) -> Database:
    return Database(path=config.db.path, echo=config.db.echo)


@app.callback()
def main(
    ctx: typer.Context,
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to YAML config (default ~/.canary/config.yaml)"
    ),
) -> None:
    """Canary — Centralized Honeypot Aggregation & MITRE ATT&CK Threat Correlation."""
    ctx.obj = Config.load(config)


@app.command()
def version() -> None:
    """Show Canary version."""
    console.print(f"Canary v{__version__}")


@app.command()
def init(ctx: typer.Context) -> None:
    """Initialize default config and database."""
    config: Config = ctx.obj
    path = config.ensure_default()
    db = _get_db(config)
    asyncio.run(db.connect())
    asyncio.run(db.disconnect())
    console.print(
        f"[green]Initialized[/] config at [bold]{path}[/] and database [bold]{config.db.path}[/]"
    )


@app.command()
def serve(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
    token: str | None = typer.Option(None, "--token", help="Require X-API-Token header"),
) -> None:
    """Start the ingestion API (POST /api/v1/events)."""
    from aiohttp import web

    from canary.ingest.api import create_app

    config: Config = ctx.obj

    async def runner() -> None:
        db = _get_db(config)
        await db.connect()
        pipeline = Pipeline(db)

        async def on_event(raw):
            return await pipeline.ingest(raw)

        web_app = create_app(on_event, api_token=token or config.server.api_token)
        runner_obj = web.AppRunner(web_app)
        await runner_obj.setup()
        site = web.TCPSite(runner_obj, host=host, port=port)
        await site.start()
        console.print(f"[green]Canary ingestion API[/] on http://{host}:{port}/api/v1/events")
        try:
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        await runner_obj.cleanup()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        console.print("[yellow]Stopping…[/]")


@app.command()
def web(
    ctx: typer.Context,
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(5000, "--port"),
) -> None:
    """Start the Flask dashboard (read-only)."""
    from canary.web.server import create_web_app

    config: Config = ctx.obj
    db = _get_db(config)
    asyncio.run(db.connect())
    flask_app = create_web_app(db)
    console.print(f"[green]Canary dashboard[/] on http://{host}:{port}/")
    flask_app.run(host=host, port=port)


@app.command()
def tui(
    ctx: typer.Context,
    refresh: float = typer.Option(5.0, "--refresh", "-r"),
) -> None:
    """Interactive live dashboard (Rich TUI)."""
    from canary.cli.dashboard import run_tui

    config: Config = ctx.obj
    db = _get_db(config)
    asyncio.run(db.connect())
    run_tui(db, refresh=refresh)


@app.command()
def ingest(
    ctx: typer.Context,
    event: Path = typer.Argument(..., help="JSON file or raw JSON string"),
) -> None:
    """Ingest a single honeypot event from a file or inline string."""
    config: Config = ctx.obj
    if event.exists():
        payload = json.loads(event.read_text(encoding="utf-8"))
    else:
        try:
            payload = json.loads(str(event))
        except json.JSONDecodeError as exc:
            raise typer.BadParameter("Provide a path to a JSON file or a JSON string") from exc

    db = _get_db(config)
    asyncio.run(db.connect())
    pipeline = Pipeline(db)
    result = asyncio.run(pipeline.ingest(payload))
    if result is None:
        raise IngestionError("Could not ingest event")
    console.print(
        f"[green]Ingested[/] event #{result.id} | attacker={result.src_ip} "
        f"technique={result.technique or '-'} tool={result.tool or '-'}"
    )


@app.command()
def top(
    ctx: typer.Context,
    limit: int = typer.Option(10, "--limit", "-n"),
) -> None:
    """Show top attackers by risk score."""
    config: Config = ctx.obj
    db = _get_db(config)
    asyncio.run(db.connect())
    rows = asyncio.run(db.list_attackers(limit=limit))
    _print_attackers(rows)
    asyncio.run(db.disconnect())


@app.command()
def profile(ctx: typer.Context, key: str = typer.Argument(...)) -> None:
    """Show a full profile for one attacker key."""
    config: Config = ctx.obj
    db = _get_db(config)
    asyncio.run(db.connect())
    row = asyncio.run(db.get_attacker(key))
    if row is None:
        console.print(f"[red]No attacker with key {key!r}[/]")
        raise typer.Exit(1)
    state = AttackerState(**row)
    console.print(Panel(f"[bold cyan]{state.key}[/]", title="Attacker", border_style="cyan"))
    console.print(f"Sources: {', '.join(state.src_ips or ['-'])}")
    console.print(
        f"Honeypots: {', '.join(state.honeypots_hit or ['-'])}  "
        f"Protocols: {', '.join(state.protocols or ['-'])}"
    )
    console.print(
        f"Events: {state.event_count}  Auth failures: {state.auth_failures}  "
        f"Commands: {state.command_count}  Score: [bold green]{state.score}[/]"
    )
    console.print(
        f"Usernames: {', '.join(state.usernames or ['-'])}  "
        f"Passwords: {', '.join(state.passwords or ['-'])}"
    )
    console.print(f"Tools: {', '.join(state.tools or ['-'])}")
    for t in state.techniques:
        info = technique_info(t)
        if info:
            console.print(
                f"  [bold]{info['id']}[/] {info['name']} · {tactic_label(info['tactic'])}"
            )
    asyncio.run(db.disconnect())


@app.command()
def export(
    ctx: typer.Context,
    fmt: str = typer.Argument(..., help="stix|csv"),
    name: str = typer.Option("canary-iocs", "--name", "-n", help="Output base name"),
) -> None:
    """Export IOCs (stix or csv)."""
    config: Config = ctx.obj
    db = _get_db(config)
    asyncio.run(db.connect())
    rows = asyncio.run(db.list_attackers(limit=500))
    states = [AttackerState(**r) for r in rows]

    if fmt == "stix":
        target = Path(name + ".json")
        bundle = build_bundle(states)
        target.write_text(json.dumps(bundle, indent=2))
        console.print(f"[green]Wrote STIX bundle[/] to {target}")
    elif fmt == "csv":
        target = Path(name + ".csv")
        write_csv(attacker_csv(states), str(target))
        console.print(f"[green]Wrote CSV[/] to {target}")
    else:
        raise typer.BadParameter("fmt must be stix or csv")
    asyncio.run(db.disconnect())


def _print_attackers(rows: list[dict]) -> None:
    if not rows:
        console.print("[yellow]No attackers recorded yet.[/]")
        return
    table = Table(title="Top attackers", header_style="bold cyan")
    table.add_column("Key")
    table.add_column("Honeypots")
    table.add_column("Techniques")
    table.add_column("Tools")
    table.add_column("Events", justify="right")
    table.add_column("Score", justify="right")
    for r in rows:
        table.add_row(
            r["key"],
            ",".join(r["honeypots_hit"]) or "-",
            ",".join(r["techniques"]) or "-",
            ",".join(r["tools"]) or "-",
            str(r["event_count"]),
            str(r["score"]),
        )
    console.print(table)
