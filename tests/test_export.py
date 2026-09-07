"""Tests for STIX export and config defaults."""

from __future__ import annotations

import json

import pytest

from canary.core.config import Config
from canary.core.models import AttackerState
from canary.export.csv import attacker_csv
from canary.export.stix import build_bundle


def _state(key: str, score: int = 10) -> AttackerState:
    return AttackerState(
        key=key,
        src_ips=[key],
        honeypots_hit=["voltron-ssh"],
        techniques=["T1110"],
        tactics=["credential-access"],
        event_count=3,
        score=score,
    )


class TestStix:
    def test_bundle_structure(self) -> None:
        bundle = build_bundle([_state("203.0.113.7")])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert any(o["type"] == "indicator" for o in bundle["objects"])
        assert any(o["type"] == "ipv4-addr" for o in bundle["objects"])

    def test_bundle_json_serializable(self) -> None:
        json.dumps(build_bundle([_state("198.51.100.4")]))

    def test_deduplicated_ips(self) -> None:
        bundle = build_bundle([_state("203.0.113.7"), _state("203.0.113.7")])
        ips = [o for o in bundle["objects"] if o["type"] == "ipv4-addr"]
        assert len(ips) == 1


class TestCsv:
    def test_rows(self) -> None:
        rows = attacker_csv([_state("203.0.113.7")])
        assert rows[0]["key"] == "203.0.113.7"
        assert rows[0]["score"] == 10
        assert rows[0]["src_ips"] == "203.0.113.7"


class TestConfig:
    def test_defaults(self) -> None:
        cfg = Config()
        assert cfg.server.port == 8080
        assert cfg.db.path == "canary.db"

    def test_load_missing_file_returns_defaults(self, tmp_path) -> None:
        cfg = Config.load(tmp_path / "nonexistent.yaml")
        assert cfg.server.host == "127.0.0.1"

    def test_invalid_yaml_raises(self, tmp_path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("{invalid: [unclosed")
        from canary.core.errors import ConfigError

        with pytest.raises(ConfigError):
            Config.load(bad)
