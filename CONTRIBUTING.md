# Contributing to Canary

Thanks for considering a contribution! Canary is a defensive, blue-team honeypot
correlation platform.

## Ground rules

- Canary **never** initiates connections, scans networks, or performs active
  engagement. Feature requests that make it aggressive will be rejected.
- Ingestion data is treated as untrusted. Never execute, evaluate, or shell out
  with attacker-controlled strings.
- Keep the zero-dependency-lite ethos: prefer stdlib unless a dependency is
  clearly justified.

## Development setup

```bash
make dev        # pip install -e ".[dev]"
make test       # pytest
make lint       # ruff check
make format     # ruff format
make typecheck  # mypy
```

## Submitting changes

1. Fork & create a branch (`feature/...` or `fix/...`).
2. Add tests under `tests/` covering your change.
3. Ensure `make test`, `make lint`, `make format`, `make typecheck` all pass.
4. Open a PR describing the change and the motivation.

## Adding ATT&CK rules

Technique rules live in `canary/attack/rules.py`. Each rule is a `TechniqueRule`
with a regex, a technique ID from `ATTACK_MATRIX` in `canary/attack/matrix.py`,
and a tactic. Keep regexes anchored and specific to avoid false positives.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities responsibly.