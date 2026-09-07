"""HTTP ingestion API for Canary (aiohttp server)."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from aiohttp import web

if TYPE_CHECKING:
    from aiohttp.web_app import Application
    from aiohttp.web_request import Request
    from aiohttp.web_response import Response

RawHandler = Callable[[dict[str, Any]], Awaitable[Any]]


def create_app(
    on_event: RawHandler,
    api_token: str | None = None,
) -> Application:
    """Build the aiohttp app exposing POST /api/v1/events.

    `on_event` receives the raw JSON payload (a dict) and is expected to
    normalize, enrich, persist and correlate it (typically the Pipeline).
    """
    app = web.Application()

    async def health(_: Request) -> Response:
        return web.json_response({"status": "ok", "service": "canary"})

    async def ingest(request: Request) -> Response:
        if api_token:
            provided = request.headers.get("X-API-Token", "")
            if provided != api_token:
                return web.json_response({"error": "unauthorized"}, status=401)
        try:
            payload = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "invalid json"}, status=400)
        if not isinstance(payload, dict):
            return web.json_response({"error": "payload must be a JSON object"}, status=400)

        try:
            event = await on_event(payload)
        except Exception:
            return web.json_response({"error": "processing failed"}, status=500)

        return web.json_response(
            {
                "status": "accepted",
                "event_id": getattr(event, "id", None),
                "technique": getattr(event, "technique", None),
                "tool": getattr(event, "tool", None),
            },
            status=201,
        )

    app.router.add_get("/api/v1/health", health)
    app.router.add_post("/api/v1/events", ingest)
    app.router.add_get("/", health)
    return app
