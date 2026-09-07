"""Flask web dashboard for Canary."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from flask import Flask, Response, jsonify, render_template

from canary.attack.matrix import technique_info
from canary.core.models import AttackerState
from canary.export.stix import build_bundle

if TYPE_CHECKING:
    from canary.core.db import Database


def create_web_app(db: Database) -> Flask:
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    def _run(coro: Any) -> Any:
        return asyncio.run(coro)

    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/api/attackers")
    def api_attackers() -> Response:
        attackers = _run(db.list_attackers(limit=50))
        return jsonify([_decorate(a) for a in attackers])

    @app.route("/api/attacker/<key>")
    def api_attacker(key: str) -> Any:
        attacker = _run(db.get_attacker(key))
        if attacker is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(_decorate(attacker))

    @app.route("/api/stats")
    def api_stats() -> Response:
        events = _run(db.event_count())
        attackers = _run(db.attacker_count())
        return jsonify({"events": events, "attackers": attackers})

    @app.route("/api/events")
    def api_events() -> Response:
        events = _run(db.list_events(limit=200))
        return jsonify(events)

    @app.route("/api/export/stix")
    def api_export_stix() -> Response:
        rows = _run(db.list_attackers(limit=500))
        states = [AttackerState(**r) for r in rows]
        bundle = build_bundle(states)
        return jsonify(bundle)

    return app


def _decorate(attacker: dict) -> dict:
    details = [technique_info(t) for t in attacker.get("techniques", [])]
    attacker["technique_names"] = [d["name"] for d in details if d]
    return attacker
