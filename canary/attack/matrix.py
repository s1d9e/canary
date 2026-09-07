"""MITRE ATT&CK matrix knowledge base (slim local subset)."""

from __future__ import annotations

# technique_id -> (name, tactic)
ATTACK_MATRIX: dict[str, tuple[str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1110": ("Brute Force", "credential-access"),
    "T1078": ("Valid Accounts", "credential-access"),
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1053": ("Scheduled Task/Job", "execution"),
    "T1204": ("User Execution", "execution"),
    "T1547": ("Boot or Logon Autostart", "persistence"),
    "T1136": ("Create Account", "persistence"),
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1562": ("Impair Defenses", "defense-evasion"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1070": ("Indicator Removal on Host", "defense-evasion"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1057": ("Process Discovery", "discovery"),
    "T1005": ("Data from Local System", "collection"),
    "T1021": ("Remote Services", "lateral-movement"),
    "T1090": ("Proxy", "command-and-control"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1560": ("Archive Collected Data", "collection"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1489": ("Service Stop", "impact"),
}


def technique_info(technique_id: str | None) -> dict[str, str] | None:
    """Return {id, name, tactic} for a technique id, or None."""
    if not technique_id:
        return None
    entry = ATTACK_MATRIX.get(technique_id)
    if entry is None:
        return {"id": technique_id, "name": technique_id, "tactic": "unknown"}
    name, tactic = entry
    return {"id": technique_id, "name": name, "tactic": tactic}


def tactic_label(tactic: str | None) -> str:
    """Human-readable tactic label."""
    if not tactic:
        return "Unknown"
    from canary.attack.rules import TACTIC_LABELS

    return TACTIC_LABELS.get(tactic, tactic)
