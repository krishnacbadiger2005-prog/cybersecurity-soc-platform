# Cybersecurity Portfolio & SOC Telemetry Platform

A dual-service Cyber Defense & Security Operations Center (SOC) monitoring platform. It pairs an authenticated web application with a live threat-detection and audit-log analysis laboratory.

---

## 🌟 Overview & Architecture

The platform consists of two microservices communicating through a shared telemetry SQLite database:

1. **Portfolio Web Application (`portfolio-app`)** [Port `5000`]:
   - User registration and authentication with secure password hashing (`PBKDF2`/`scrypt` via `werkzeug.security`).
   - Session-protected portfolio showcase with quick-launch access to the SOC monitoring lab.
   - Real-time telemetry interceptor recording every authentication attempt (`SUCCESS` or `FAILED`), IP address, and timestamp into `login_events`.

2. **SOC Security Lab & Telemetry Dashboard (`security-lab`)** [Port `5001`]:
   - **Automated Threat Detection Engine (`detector.py`)**: Sliding-window heuristic detecting brute-force attacks ($\ge 5$ failed attempts within 10 minutes) across both live telemetry and historical logs.
   - **Linux Syslog Ingestion Pipeline (`log_parser.py`)**: Parses Linux SSH authentication logs (`/var/log/auth.log`) with deterministic SHA-256 event fingerprinting to guarantee duplicate-free ingestion.
   - **SOC Analytics Dashboard**: Live KPI metric cards, source and time-range filtering (`15m`, `1h`, `24h`, `7d`, `all`), activity timeline, attacking IP leaderboard, and active alerts.
   - **Executive Reporting Engine (`reports.py`)**: Generates audit-ready CSV exports and styled PDF reports powered by ReportLab.
   - **REST Telemetry API (`/api/metrics`)**: Machine-to-machine JSON endpoint for SIEM integration or automated testing.

---

## 🛠️ Tech Stack & Protocols

- **Backend**: Python 3.12, Flask, SQLite3, Werkzeug
- **Reporting**: ReportLab (PDF generation), Python CSV
- **Containerization**: Docker, Docker Compose (Multi-container orchestration with shared volume)
- **Protocols**: HTTP/REST, Syslog (RFC 3164), SSH-2 Telemetry, TCP, IPv4, SHA-256 Fingerprinting, HMAC Signed Cookies

---

## 📁 Repository Structure

```text
├── docker-compose.yml              # Multi-container orchestration (portfolio + security-lab)
├── requirements.txt                # Workspace dependencies
├── security.db                     # Shared SQLite telemetry database
├── view_db.py                      # CLI tool to inspect DB tables, users, and audit logs
│
├── portfolio-app/                  # Microservice 1: Portfolio Web Application
│   ├── app.py                      # Flask authentication & portfolio routes
│   ├── database.py                 # Telemetry logger & DB connector
│   ├── requirements.txt            # App dependencies
│   ├── Dockerfile                  # Container definition for port 5000
│   ├── static/                     # CSS stylesheets & styling
│   └── templates/                  # Jinja2 templates (login, register, portfolio)
│
├── security-lab/                   # Microservice 2: SOC Security Operations Center
│   ├── app.py                      # SOC Dashboard server & REST API
│   ├── database.py                 # Telemetry queries & alert management
│   ├── detector.py                 # Sliding-window brute force detection engine
│   ├── log_parser.py               # Linux syslog / SSH auth log parser & deduplicator
│   ├── reports.py                  # ReportLab PDF & CSV security audit generator
│   ├── Dockerfile                  # Container definition for port 5001
│   ├── sample_logs/auth.log        # Sample Linux syslog file for testing
│   ├── static/                     # Cyber-style dark SOC dashboard styling
│   └── templates/dashboard.html    # Full SOC dashboard UI
│
├── test_app.py                     # Integration tests for Portfolio app authentication
├── test_security_lab.py            # Unit & integration tests for Security Lab queries & API
└── test_phase7_linux_parser.py     # Test suite for Linux syslog parsing & SHA-256 deduplication
```

---

## 🚀 Getting Started

### Option 1: Running with Docker Compose (Recommended)

Make sure Docker Desktop is running, then run:

```bash
docker-compose up --build
```

- **Portfolio App**: Visit [http://localhost:5000](http://localhost:5000)
- **SOC Security Lab**: Visit [http://localhost:5001/dashboard](http://localhost:5001/dashboard)

---

### Option 2: Running Locally with Python Virtual Environment

1. **Set up virtual environment**:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate

   pip install -r requirements.txt
   pip install reportlab
   ```

2. **Start the Portfolio Application**:
   ```bash
   python portfolio-app/app.py
   ```
   *Runs on port 5000.*

3. **Start the SOC Security Lab** (in another terminal):
   ```bash
   cd security-lab
   python app.py
   ```
   *Runs on port 5001.*

4. **Ingest Linux Syslog Authentication Logs**:
   ```bash
   python security-lab/log_parser.py
   ```

5. **Inspect the Database from the CLI**:
   ```bash
   python view_db.py metrics
   python view_db.py events
   ```

---

## 🧪 Testing & Verification

Run the comprehensive test suites:

```bash
# Run all tests
python -m unittest discover -s . -p "test_*.py"

# Or run individual test modules
python -m unittest test_app.py
python -m unittest test_security_lab.py
python -m unittest test_phase7_linux_parser.py
```

---

## 🛡️ License

This project is created for educational and cybersecurity demonstration purposes.
