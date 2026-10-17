# siem-logs-lab

<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">

Local detection pipeline with seven rules, temporal correlation across events, and alerts mapped to MITRE ATT&CK.

## Problem / Why it exists

Security detection is not a search engine over logs. It is correlation of events that only make sense together, with time as the common axis. A single failed login is noise; the same login followed by a successful one from another country five minutes later is an incident. This project demonstrates that correlation with rules and time windows, on synthetic data, without SIEM, agent, or cloud.

## What it does

- Loads 2,378 synthetic log events from `dados/logs-sinteticos.jsonl`.
- Applies seven detection rules (failed login, success after failure, privilege escalation, lateral movement, data exfiltration, port scan, brute force).
- Correlates events by time window per user, IP, and host.
- Maps each alert to a MITRE ATT&CK technique (T1110, T1078, T1068, T1021, T1041, T1046).
- Emits a report with the alert list, involved events, and severity.
- Runs from the CLI with `resumir` and `--saida` to save the report.

## Stack

- Python 3.10+
- PyYAML >= 6.0 (only runtime dependency)
- pytest and pytest-cov (development)
- Standard library only beyond PyYAML

## How it works

1. Normalizer reads the JSONL and validates the schema, rejecting malformed lines.
2. Rules evaluate each event against its conditions and produce candidate alerts.
3. Correlation groups candidate alerts by time window per user, IP, and host.
4. MITRE mapping assigns a technique to each correlated alert.
5. Report formats the alert list with involved events and severity.

## How to run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m siem_logs_lab resumir
python -m siem_logs_lab resumir --saida exemplos/relatorio-siem.md
python -m pytest tests/ -q
```

## Project structure

```
siem-logs-lab/
├── src/siemlab/           # package: cli, regras, correlacao, normalizador, alertas, relatorio
├── dados/                 # logs-sinteticos.jsonl (2,378 events), regras-sigma.yaml
├── docs/                  # como-funciona-deteccao.md, mitre-attack-mapeamento.md
├── exemplos/              # relatorio-siem.md (real output)
├── tests/                 # 26 tests
├── tools/                 # gerar_logs.py, verificar_aceite.py, verificar_encoding.py
├── pyproject.toml
├── requirements.txt
└── LICENSE                # MIT
```

## Trade-offs and decisions

- Rules in YAML, not in code: changing a threshold is a data edit, not a deploy.
- Temporal correlation by window, not by exact match: real attacks have jitter.
- MITRE mapping is manual, not automatic: the mapping is a judgment, not a computation.
- Synthetic data: no real logs, no privacy concern, reproducible.

## Known limitations

- Seven rules only: no machine learning, no anomaly detection beyond thresholds.
- Synthetic data: does not reflect real log volume or noise.
- No real-time: batch processing only.
- No alert deduplication: the same incident can fire multiple rules.

## License

MIT.

## Author

Kelvin Oliveira