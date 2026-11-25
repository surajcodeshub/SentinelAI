<<<<<<< HEAD
# SentinelAI – Autonomous Cyber Defense System

**Developed by:** Suraj | BCA Cyber Security | Lamrin Tech Skills University, Punjab

## Quick Start

```bash
cd SentinelAI
pip install flask scikit-learn pandas numpy
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

## Features

| Feature | Status |
|---|---|
| SOC Dashboard with live metrics | ✅ Implemented |
| Security event log viewer | ✅ Implemented |
| Brute-force attack detection | ✅ Implemented |
| Alert management (resolve/escalate) | ✅ Implemented |
| AI threat analysis engine | ✅ Implemented |
| Incident report generation | ✅ Implemented |
| Attack simulation (demo) | ✅ Implemented |
| ML anomaly detection (Isolation Forest) | ✅ Implemented |
| Live log ingestion & parsing | ✅ Implemented |
| Network scanning (Nmap) | 🔵 Proposed |

## Project Structure

```
SentinelAI/
├── app.py                  # Flask entry point
├── database.py             # SQLite database layer
├── alert_manager.py        # Alert creation & management
├── event_parser.py         # Log line parsing
├── report_generator.py     # Incident report generator
├── seed_data.py            # Demo data seeder
├── detectors/
│   └── brute_force.py      # Brute-force detection
├── ml/
│   └── anomaly_detector.py # Isolation Forest ML model
├── ai/
│   └── threat_analyzer.py  # AI threat analysis engine
├── routes/
│   ├── dashboard.py        # Page routes
│   └── api.py              # REST API endpoints
├── templates/              # Jinja2 HTML templates
└── static/                 # CSS & JavaScript
```
=======
# SentinelAI
AI-based Cyber Security Monitoring System – BCA Final Year Project
>>>>>>> 8bf48578daf32310ad2618a92fda840ec205410a
