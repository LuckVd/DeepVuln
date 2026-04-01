# DeepVuln

DeepVuln is a multi-engine vulnerability analysis platform built around three layers:

- L1 intelligence for source acquisition, tech-stack detection, attack-surface discovery, and threat intelligence
- L3 analysis combining Semgrep, CodeQL, and agent-driven review
- Reporting focused on exploitability, evidence quality, and scan transparency

## Docker Scanning

### Prerequisites

1. Ensure source code directory has proper permissions:
   ```bash
   chmod -R 777 /path/to/source/code
   ```

2. Clean build artifacts before scanning (recommended):
   ```bash
   rm -rf /path/to/source/code/target
   ```

### Base Scan (3 Engines, No LLM Verification)

```bash
docker run --rm \
  -e OPENAI_API_KEY="your-api-key" \
  -e OPENAI_BASE_URL="your-llm-endpoint" \
  -v /path/to/source/code:/target:rw \
  -v /path/to/reports:/reports \
  deepvuln:latest scan -p /target --base \
    --export "/reports/$(date +%Y%m%d_%H%M%S)_scan.json" \
    --model your-model --force-codeql-all --detailed
```

### Full Scan (3 Engines + LLM Verification + Adversarial Debate)

```bash
docker run --rm \
  -e OPENAI_API_KEY="your-api-key" \
  -e OPENAI_BASE_URL="your-llm-endpoint" \
  -v /path/to/source/code:/target:rw \
  -v /path/to/reports:/reports \
  deepvuln:latest scan -p /target --full \
    --export "/reports/$(date +%Y%m%d_%H%M%S)_scan.json" \
    --model your-model --force-codeql-all --detailed
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `--base` | Base scan: 3 engines only (Semgrep + CodeQL + Agent) |
| `--full` | Full scan: 3 engines + LLM verification + adversarial debate |
| `--export` | Export report to file |
| `--model` | LLM model name |
| `--force-codeql-all` | Force CodeQL for all detected languages |
| `--detailed` | Output detailed vulnerability information (required for full findings) |

## Development

Install the project in editable mode with development dependencies:

```bash
pip install -e .[dev]
```

Run the test suite:

```bash
pytest -q
```
