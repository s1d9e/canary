"""Attacker risk scoring."""

from __future__ import annotations

from canary.core.config import CorrelationConfig


def score_event(
    event_type: str,
    technique_detected: bool,
    new_honeypot: bool = False,
    protocol_present: bool = False,
    tool_detected: bool = False,
    config: CorrelationConfig | None = None,
) -> int:
    """Compute an incremental risk score contribution for a single event."""
    cfg = config or CorrelationConfig()
    if event_type == "auth":
        return cfg.score_auth_failure
    if event_type == "command":
        return cfg.score_command
    base = cfg.score_initial
    if technique_detected:
        base += cfg.score_technique
    if new_honeypot:
        base += cfg.score_new_honeypot
    if protocol_present:
        base += cfg.score_protocol
    if tool_detected:
        base += cfg.score_tool
    return base
