"""Pydantic data models for Canary events, sessions, and attackers."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AttackTactic(str, Enum):
    RECON = "reconnaissance"
    RESOURCE_DEV = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command-and-control"
    EXFIL = "exfiltration"
    IMPACT = "impact"


class IngestEvent(BaseModel):
    """A single raw event posted by a honeypot."""

    honeypot: str = Field(..., description="Source honeypot name, e.g. blood-web")
    protocol: str | None = Field(None, description="ssh, http, ftp, smtp, mysql, etc.")
    src_ip: str | None = Field(None, description="Attacker source IP")
    src_port: int | None = Field(None, description="Attacker source port")
    dst_ip: str | None = Field(None, description="Victim / honeypot destination IP")
    dst_port: int | None = Field(None, description="Destination port / service")
    timestamp: str | None = Field(None, description="ISO8601 UTC timestamp")
    session_id: str | None = Field(None, description="Honeypot-side session identifier")
    username: str | None = Field(None, description="Attempted username (auth events)")
    password: str | None = Field(None, description="Attempted password (auth events)")
    command: str | None = Field(None, description="Executed / attempted shell command")
    url: str | None = Field(None, description="Requested URL (HTTP honeypots)")
    user_agent: str | None = Field(None, description="HTTP user agent")
    method: str | None = Field(None, description="HTTP method")
    request_headers: dict[str, str] | None = Field(default_factory=dict)
    response_code: int | None = Field(None, description="HTTP response code served")
    data: dict[str, Any] | None = Field(
        default_factory=dict, description="Extra honeypot-specific fields"
    )
    raw: str | None = Field(None, description="Raw original log line / message")
    event_type: str = Field(
        "generic", description="auth, command, http, connection, download, file, generic"
    )

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            # Allow hostnames / empty values without hard failure; canonicalize
            return v
        return v

    def parsed_timestamp(self) -> datetime | None:
        if not self.timestamp:
            return None
        try:
            return datetime.fromisoformat(self.timestamp.replace("Z", "+00:00")).astimezone(
                timezone.utc
            )
        except ValueError:
            return None


class NormalizedEvent(BaseModel):
    """Canonical event stored after normalization."""

    id: int | None = None
    honeypot: str
    event_type: str
    protocol: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    session_id: str | None = None
    timestamp: str | None = None
    username: str | None = None
    password: str | None = None
    command: str | None = None
    url: str | None = None
    method: str | None = None
    user_agent: str | None = None
    response_code: int | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    raw: str | None = None
    technique: str | None = Field(None, description="Detected MITRE ATT&CK technique ID")
    tactic: str | None = Field(None, description="Detected MITRE ATT&CK tactic")
    tool: str | None = Field(None, description="Fingerprinted attacker tooling")
    confidence: float = Field(0.0, description="Confidence of technique mapping 0..1")


class AttackerState(BaseModel):
    """Aggregated threat view for a single attacker (keyed by identity finger)."""

    key: str = Field(..., description="Correlation key (src_ip typically)")
    src_ips: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)
    honeypots_hit: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    event_count: int = 0
    auth_failures: int = 0
    command_count: int = 0
    score: int = 0
    usernames: list[str] = Field(default_factory=list)
    passwords: list[str] = Field(default_factory=list)
