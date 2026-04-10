# Vulnerability Prioritization Dashboard

Academic graduation project for MEC focused on simulated cybersecurity operations in a smart-city-style enterprise environment.

## Features
- Flask web dashboard with dark SOC-inspired UI.
- Simulated LAN environment with approximately 200 devices across departments.
- AI-driven vulnerability prioritization (Random Forest primary, SVM and Decision Tree comparison).
- Patch management workflow and alert feeds.
- Compliance summary views (ISO/IEC 27001, NIST CSF, CIS Controls v8).
- REST API at `/api/v1/*` for charts and AJAX data access.
- Role-based access control (admin, security_analyst, network_admin, viewer).

## Integrated Security Tools

| Tool | Route | Status | Chapter Ref |
|------|-------|--------|------------|
| **Nmap** (real scan) | `/scan-results/nmap` | ✅ Active | Ch. 2, 3.7.2 |
| **OpenVAS** (GVM 22.4) | `/scan-results/openvas` | ✅ Simulated | Ch. 2 Study 4, 3.7.2 |
| **Wireshark** (PCAP parser) | `/traffic-analysis` | ✅ Active | Ch. 3.7.2 |
| **Metasploit Framework** | `/exploit-verification` | ✅ Simulated | Ch. 2, 3.7.2 |
| **Kali Linux Toolkit** | `/exploit-verification` (sidebar) | ✅ Simulated | Ch. 2.4.1 |
| **Snort / Suricata IDS** | `/ids-engine` | ✅ Simulated | Ch. 3.4.2 |
| **Splunk SIEM** (query interface) | `/siem-logs` | ✅ Simulated | Ch. 3.7.2 |
| **Firewall Rules Engine** (Cisco ASA-style) | `/firewall-rules` | ✅ Simulated | Ch. 3.4.2 |
| **VPN & TLS Inspection** (IPsec/OpenVPN/WireGuard) | `/vpn-monitoring` | ✅ Simulated | Ch. 3.4.2, 3.7.2 |
| **Threat Intelligence** (CISA KEV, OTX, AbuseIPDB, MISP, VT, Shodan) | `/threat-intel` | ✅ Simulated | Ch. 3.4 |
| **DFIR / Incident Response** (Kanban board) | `/incident-response` | ✅ Simulated | Ch. 3.4 |
| **Endpoint Security / EDR** (CrowdStrike-style) | `/endpoint-security` | ✅ Simulated | Ch. 3.4 (ESTHT) |
| **GNS3 Network Simulation** | `/network-topology` (tab) | ✅ Simulated | Ch. 1.3.4 |
| **MITRE ATT&CK Mapping** | `/mitre-attack` | ✅ Active | Ch. 3 |
| **AI Chat Assistant** | `/ai-chat` | ✅ Active | Ch. 3 |

## Tech Stack
- Backend: Flask + SQLAlchemy + Flask-Login + Flask-Migrate
- Frontend: HTML/CSS/JavaScript, Chart.js, DataTables
- AI/ML: scikit-learn, pandas, numpy, joblib
- DB: SQLite (default), PostgreSQL supported via `DATABASE_URL`

## Quick Start

**Prerequisites:** Python 3.10+ recommended. On macOS with Homebrew, use `python3` (the `python` / `pip` commands may be missing). Homebrew’s Python is *externally managed* (PEP 668), so install dependencies inside a project virtual environment—not with system-wide `pip`.

1. **Clone and enter the project directory**

2. **Create and activate a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # macOS / Linux
   ```
   On Windows (PowerShell): `.venv\Scripts\Activate.ps1`

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment variables (optional but recommended)**  
   Copy `.env.example` to `.env` and adjust values (e.g. `SECRET_KEY`, `NMAP_BINARY_PATH` if you use real scans).

5. **Seed the database and ML artifacts**
   ```bash
   python seed_data.py
   ```
   This can take several minutes on first run.

6. **Run the app**
   ```bash
   python run.py
   ```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

**Tip:** After `source .venv/bin/activate`, `python` and `pip` refer to the venv. To leave the venv: `deactivate`.

## Default Users
- admin / admin
- analyst / analyst123
- netadmin / netadmin123
- viewer / viewer123

## Project Structure
- `app/` Flask app package (models, routes, ai, scanners, templates, static)
- `data/` simulated tool outputs and generated topology/dataset
- `ml_models/` trained model artifacts
- `tests/` basic route, parser, and AI tests
- `seed_data.py` full simulation data bootstrap

## Notes
- All scanning and exploit data is simulated by default, but REAL Nmap scanning is now supported.
- Arabic strings are supported through UTF-8 content handling.
- The app is intended for education and demonstration, not production security operations.

### Installing Nmap for Real Scanning

To use the real network scanning features, you must have Nmap installed on your system.

**macOS:**
```bash
brew install nmap
```

**Ubuntu/Linux:**
```bash
sudo apt install nmap
```

**Note:** Some scan types (OS detection with `-O`) may require running with sudo:
```bash
sudo .venv/bin/python run.py
```

### Running a Real Scan

1. Connect your machine to the network you want to scan.
2. Open the dashboard (http://127.0.0.1:5000).
3. The scanner will auto-detect your network.
4. Select scan type and click "Start Scan".
5. Wait for the scan to complete (2-5 minutes).
6. View discovered devices in the **Devices** page.
7. Check **Scan Results** (Security Tools > Scan Results) for detailed port/service information.
