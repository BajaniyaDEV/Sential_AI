# SentinelAI

SentinelAI is an intelligent cybersecurity platform designed to collect security logs, detect suspicious behavior, identify anomalies with machine learning, map findings to MITRE ATT&CK, explain incidents with AI, and present results in a dashboard.

## Phase 1: project setup

This repository lays the foundation for the project structure and starter modules. The goal is to set up a clean development layout before adding real detection logic, database integration, and dashboard features.

## Project structure

```text
SentinelAI/
├── data/
│   ├── raw_logs/
│   └── processed_logs/
├── backend/
│   ├── main.py
│   ├── models/
│   ├── services/
│   └── database/
├── detection/
│   ├── brute_force.py
│   ├── suspicious_ip.py
│   └── anomaly_detection.py
├── ai_engine/
│   ├── incident_analyzer.py
│   └── mitre_mapper.py
├── dashboard/
│   └── app.py
├── reports/
├── requirements.txt
├── README.md
```

## Tech stack

- Python
- FastAPI
- SQLite
- Pandas
- Scikit-learn
- Streamlit
- Docker (planned for later phases)

## Getting started

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the backend:
   ```bash
   python backend/main.py
   ```
4. Run the dashboard:
   ```bash
   streamlit run dashboard/app.py
   ```

## Roadmap

- Phase 1: project skeleton and starter modules
- Phase 2: log ingestion and preprocessing
- Phase 3: detection rules and anomaly models
- Phase 4: ATT&CK mapping and incident analysis
- Phase 5: dashboard and reporting

## Phase 2: log ingestion and preprocessing

The Phase 2 ingester converts supported authentication logs into normalized
records with `timestamp`, `user`, `event`, `ip`, and `source_line` fields.
`INFO ... Login successful` becomes `Success`; `FAILED ... Login failed`
becomes `Failed`. Timestamps and IP addresses are validated, and malformed
lines are reported without stopping ingestion by default.

Use the included sample data:

```bash
python -m backend.services.ingest_logs data/raw_logs/sample_auth.log
```

This writes `data/processed_logs/sample_auth.csv`. Choose JSON or another
destination when needed:

```bash
python -m backend.services.ingest_logs data/raw_logs/sample_auth.log --format json --output data/processed_logs/events.json
```

For API callers, `POST /logs/parse` accepts `{"logs": "..."}` and returns
the normalized events plus any line-level parse errors.

## Phase 3: threat detection

`POST /logs/analyze` parses the same request body and runs four detection
methods: five failed attempts for the same user/IP in five minutes
(brute-force), five failures from a public IP (suspicious IP), a successful
login after repeated failures, and Isolation Forest anomaly detection when at
least five events are available. The response contains parsed events, alerts,
and alert counts by detector.

## Phase 5: SQLite persistence

`data/sentinelai.db` is created automatically when data is stored. It contains
`events`, `alerts`, and `incidents` tables. Use `POST /logs/analyze-and-store`
with the same body as `/logs/analyze` to persist an ingestion run. The API also
provides `GET /alerts`, `GET /alerts/{alert_id}`, `PATCH
/alerts/{alert_id}/status`, `GET /incidents`, `POST /incidents`, and `GET
/incidents/{incident_id}`.
