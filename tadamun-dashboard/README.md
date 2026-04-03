# Tadamun Smart City Vulnerability Prioritization Dashboard

Academic graduation project for MEC focused on simulated cybersecurity operations in Tadamun Smart City (مدينة تضامن الذكية), Muscat, Oman.

## Features
- Flask web dashboard with dark SOC-inspired UI.
- Simulated LAN environment with approximately 200 devices across departments.
- AI-driven vulnerability prioritization (Random Forest primary, SVM and Decision Tree comparison).
- Patch management workflow and alert feeds.
- Compliance summary views (ISO/IEC 27001, NIST CSF, CIS Controls v8).
- REST API at `/api/v1/*` for charts and AJAX data access.
- Role-based access control (admin, security_analyst, network_admin, viewer).

## Tech Stack
- Backend: Flask + SQLAlchemy + Flask-Login + Flask-Migrate
- Frontend: HTML/CSS/JavaScript, Chart.js, DataTables
- AI/ML: scikit-learn, pandas, numpy, joblib
- DB: SQLite (default), PostgreSQL supported via `DATABASE_URL`

## Quick Start
```bash
pip install -r requirements.txt
python seed_data.py
python run.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

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
- All scanning and exploit data is simulated.
- Arabic strings are supported through UTF-8 content handling.
- The app is intended for education and demonstration, not production security operations.
