"""Attacker tooling fingerprinting from event signatures."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from canary.core.models import IngestEvent, NormalizedEvent


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


TOOL_PATTERNS: list[tuple[str, list[re.Pattern[str]]]] = [
    ("nuclei", [_re(r"nuclei")]),
    ("sqlmap", [_re(r"sqlmap")]),
    ("nmap", [_re(r"nmap|Nmap")]),
    ("masscan", [_re(r"masscan")]),
    ("hydra", [_re(r"hydra")]),
    ("john", [_re(r"john the ripper|\bjohn\b")]),
    ("metasploit", [_re(r"metasploit|msfconsole|meterpreter")]),
    ("mimikatz", [_re(r"mimikatz")]),
    ("curl", [_re(r"curl/|libcurl")]),
    ("wget", [_re(r"wget/")]),
    ("python-requests", [_re(r"python-requests|requests/")]),
    ("go-http-client", [_re(r"Go-http-client")]),
    ("nikto", [_re(r"nikto")]),
    ("gobuster", [_re(r"gobuster|dirbuster")]),
    ("ffuf", [_re(r"\bffuf\b")]),
    ("xsstrike", [_re(r"xsstrike")]),
    ("cameleon", [_re(r"cameleon")]),
    ("zmap", [_re(r"zmap")]),
    ("shodan", [_re(r"shodan")]),
    ("census", [_re(r"censys")]),
    ("maltego", [_re(r"maltego")]),
]


def fingerprint(text: str | None) -> str | None:
    """Return the most likely known tool name for an event's text, or None.

    `text` is built by the caller from UA + command + raw. Unknown strings
    are left to the CLI heuristics instead.
    """
    if not text:
        return None
    for tool, patterns in TOOL_PATTERNS:
        for rx in patterns:
            if rx.search(text):
                return tool
    return None


def fingerprint_event(event: NormalizedEvent | IngestEvent) -> str | None:
    """Fingerprint a NormalizedEvent/IngestEvent by combining its fields."""
    parts = [
        event.user_agent or "",
        event.command or "",
        event.raw or "",
        (event.data or {}).get("ua") or "",
    ]
    return fingerprint(" | ".join(parts))
