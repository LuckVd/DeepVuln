# DeepVuln

DeepVuln is a multi-engine vulnerability analysis platform built around three layers:

- L1 intelligence for source acquisition, tech-stack detection, attack-surface discovery, and threat intelligence
- L3 analysis combining Semgrep, CodeQL, and agent-driven review
- Reporting focused on exploitability, evidence quality, and scan transparency

## Development

Install the project in editable mode with development dependencies:

```bash
pip install -e .[dev]
```

Run the test suite:

```bash
pytest -q
```
