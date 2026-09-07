"""MITRE ATT&CK technique detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from canary.core.models import IngestEvent, NormalizedEvent

# Tactic labels used throughout Canary
TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


@dataclass(frozen=True)
class TechniqueRule:
    technique: str
    name: str
    tactic: str
    pattern: re.Pattern[str]


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


RULES: list[TechniqueRule] = [
    # === Initial Access ===
    TechniqueRule(
        "T1190",
        "Exploit Public-Facing Application",
        "initial-access",
        _rx(r"(cve-\\d{4}-\\d+|exploit|shellshock|struts|log4j|jndi)"),
    ),
    TechniqueRule(
        "T1133", "External Remote Services", "initial-access", _rx(r"(vpn|rdp|remote desktop)")
    ),
    # === Credential Access ===
    TechniqueRule(
        "T1110",
        "Brute Force",
        "credential-access",
        _rx(
            r"(brute[- ]?force|login attempt|auth fail|failed password|"
            r"password (test|guess)|toor|admin1?23|123456)"
        ),
    ),
    TechniqueRule(
        "T1078",
        "Valid Accounts",
        "credential-access",
        _rx(r"(login success|authenticated|root:.*(?!fail))"),
    ),
    # === Execution ===
    TechniqueRule(
        "T1059",
        "Command and Scripting Interpreter",
        "execution",
        _rx(
            r"(sh -c|bash -c|/bin/sh|/bin/bash|cmd\.exe|powershell(-)?exe|"
            r"python -c|\bperl -e|\bawk|\bsed)"
        ),
    ),
    TechniqueRule(
        "T1053",
        "Scheduled Task/Job",
        "execution",
        _rx(r"(crontab|cron|at\s|schtasks|systemd timer)"),
    ),
    TechniqueRule("T1204", "User Execution", "execution", _rx(r"(wget|curl)(\s|$|-)")),
    # === Persistence ===
    TechniqueRule(
        "T1547",
        "Boot or Logon Autostart",
        "persistence",
        _rx(r"(\.bashrc|\.profile|autorun|startup\s+script|init\.rc)"),
    ),
    TechniqueRule(
        "T1136", "Create Account", "persistence", _rx(r"(useradd|adduser|net user|user /add)")
    ),
    # === Privilege Escalation ===
    TechniqueRule(
        "T1548",
        "Abuse Elevation Control Mechanism",
        "privilege-escalation",
        _rx(r"(sudo|setuid|pkexec|runas)"),
    ),
    TechniqueRule(
        "T1068",
        "Exploitation for Privilege Escalation",
        "privilege-escalation",
        _rx(r"(dirty[- ]?cow|overlayfs|polkit|sudo exploit)"),
    ),
    # === Defense Evasion ===
    TechniqueRule(
        "T1562",
        "Impair Defenses",
        "defense-evasion",
        _rx(r"(disable .*firewall|iptables -F|kill .*agent|rm /var/log|clear_logs|stop.*service)"),
    ),
    TechniqueRule(
        "T1027",
        "Obfuscated Files or Information",
        "defense-evasion",
        _rx(r"(base64 -d|xxd -r|\| base64|0x[0-9a-f]{8,}|\\\\x[0-9a-f]{2})"),
    ),
    TechniqueRule(
        "T1070",
        "Indicator Removal on Host",
        "defense-evasion",
        _rx(r"(rm -rf|history -c|unset HISTFILE|shred|wipe\s)"),
    ),
    # === Discovery ===
    TechniqueRule(
        "T1046",
        "Network Service Discovery",
        "discovery",
        _rx(r"(nmap|masscan|netdiscover|arp -a|ip neigh|for .* (port|scan)|nc -z|scanme)"),
    ),
    TechniqueRule(
        "T1082",
        "System Information Discovery",
        "discovery",
        _rx(r"(uname -a|cat /proc/cpuinfo|cat /etc/os-release|hostnamectl|ver\b|systeminfo)"),
    ),
    TechniqueRule(
        "T1057", "Process Discovery", "discovery", _rx(r"(ps aux|tasklist|top -b|pgrep)")
    ),
    TechniqueRule(
        "T1005",
        "Data from Local System",
        "collection",
        _rx(r"(cat /etc/passwd|cat /etc/shadow|\.ssh/id_rsa|\.ssh/authorized_keys|find .* -name)"),
    ),
    # === Lateral Movement ===
    TechniqueRule(
        "T1021",
        "Remote Services",
        "lateral-movement",
        _rx(r"(ssh\s+.*@|scp\s|wget .*ssh|net use \\\\)"),
    ),
    TechniqueRule(
        "T1090",
        "Proxy",
        "command-and-control",
        _rx(r"(proxychains|socks|tunnel|ssh -R|ssh -L|chisel|frp\b|ngrok|nc -l)"),
    ),
    TechniqueRule(
        "T1105",
        "Ingress Tool Transfer",
        "command-and-control",
        _rx(r"(curl .*\\-o|wget .*\\-O|wget .*\\.(sh|py|elf|tar|zip)|mimikatz|nc.exe|ncat)"),
    ),
    # === Collection / Exfil ===
    TechniqueRule(
        "T1560", "Archive Collected Data", "collection", _rx(r"(tar czf|zip -r|gzip -c)")
    ),
    TechniqueRule(
        "T1041",
        "Exfiltration Over C2 Channel",
        "exfiltration",
        _rx(r"(curl .*post|wget .*post|base64.*url|upload|pastebin|webhook)"),
    ),
    # === Impact ===
    TechniqueRule(
        "T1486",
        "Data Encrypted for Impact",
        "impact",
        _rx(r"(ransomware|encrypt.*file|\.encrypt|bitcoin|wallet)"),
    ),
    TechniqueRule(
        "T1489",
        "Service Stop",
        "impact",
        _rx(r"(systemctl stop|service\s+\w+\s+stop|killall|pkill)"),
    ),
]


def detect_techniques(event: NormalizedEvent | IngestEvent) -> tuple[str | None, str | None, float]:
    """Run all technique rules against an event; return best (technique, tactic, confidence)."""
    text_parts = []
    for value in (
        event.command,
        event.raw,
        event.url,
        event.username,
        event.password,
        event.method,
    ):
        if value:
            text_parts.append(str(value))
    text = "\n".join(text_parts)

    best: tuple[TechniqueRule, float] | None = None
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            length = min(len(m.group(0)), 24) / 24.0
            conf = 0.5 + 0.5 * length
            if best is None or conf > best[1]:
                best = (rule, conf)
    if best is None:
        return None, None, 0.0
    rule, conf = best
    return rule.technique, rule.tactic, round(conf, 2)
