---
name: Full Dashboard Upgrade
overview: "Transform the security dashboard from a mostly static UI into a fully working tool with: real network device discovery (no root/nmap required), realistic attack scenario simulations, and a Gemini AI chat assistant for vulnerability analysis."
todos:
  - id: light-scanner
    content: Create app/scanners/light_scanner.py — pure-Python ping+socket scanner, no root required
    status: completed
  - id: real-scanner-fallback
    content: Modify real_scanner.py to fall back to light_scanner when nmap is unavailable
    status: completed
  - id: attack-scenarios-route
    content: Add /attack-scenarios route to security_tools.py with 8 realistic scenario data
    status: completed
  - id: attack-scenarios-template
    content: Create attack_scenarios.html template with cards for each attack scenario
    status: completed
  - id: gemini-config
    content: Add GEMINI_API_KEY and GEMINI_MODEL to config.py
    status: completed
  - id: ai-chat-route
    content: Create app/routes/ai_chat.py with GET /ai-chat and POST /api/v1/ai/chat
    status: completed
  - id: ai-chat-template
    content: Create app/templates/ai_chat/index.html with full chat UI
    status: completed
  - id: register-blueprint
    content: Register ai_chat_bp in app/__init__.py
    status: completed
  - id: nav-updates
    content: "Update base.html nav: add Attack Scenarios and AI Assistant links"
    status: completed
  - id: vuln-ask-ai
    content: Add Ask AI button to vulnerability detail page with CVE context
    status: completed
isProject: false
---

# Full Dashboard Upgrade Plan

## What We're Adding

### 1. Real Network Scanner (No Root / No Nmap Required)
New file: `app/scanners/light_scanner.py`

Pure-Python scanner that works without any special permissions:
- **Host discovery**: `subprocess ping` sweep across the local `/24` subnet
- **Port scanning**: `socket.connect()` on ~20 common ports (22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5900, 8080…)
- **Hostname**: `socket.gethostbyaddr()` reverse DNS
- **MAC/Vendor**: reads OS ARP cache via `arp -a` (macOS/Linux — no root needed)
- **Device typing**: heuristic from open ports (same logic as `guess_device_type` in `real_scanner.py`)

Modify `app/scanners/real_scanner.py`:
- Wrap nmap call in `try/except`; if `FileNotFoundError` or returncode != 0, fall back to `light_scanner.py`
- Results are stored in the same `scan_state` dict and persisted to DB via existing `save_scan_to_db()`

### 2. Attack Scenarios Page
New route `GET /attack-scenarios` in [`app/routes/security_tools.py`](app/routes/security_tools.py)

New template `app/templates/security_tools/attack_scenarios.html`

Page shows **8 realistic scenario cards**:

| Scenario | Type | MITRE | Severity |
|---|---|---|---|
| ARP Cache Poisoning | MITM | T1557 | Critical |
| SYN Flood / DoS | DoS | T1498 | High |
| SSH Brute Force | Credential Access | T1110 | High |
| DNS Spoofing | MITM | T1557.002 | Critical |
| Port Scan Reconnaissance | Discovery | T1046 | Medium |
| SMB Exploit (EternalBlue) | Lateral Movement | T1021.002 | Critical |
| Rogue AP / Evil Twin | MITM | T1557 | High |
| Malware C2 Beacon | Command & Control | T1071 | Critical |

Each card contains:
- How the attack works (technical explanation)
- How to detect it (signs/indicators)
- How to mitigate/protect (concrete steps)
- Randomly assigned to 1-2 seeded devices from the DB for realism

This is **simulation/training data** shown clearly with a badge ("Simulated Scenario"), not fake live data.

### 3. Gemini AI Chat Assistant
New files:
- `app/routes/ai_chat.py` — blueprint with `GET /ai-chat` and `POST /api/v1/ai/chat`
- `app/templates/ai_chat/index.html` — full chat UI

How it works:
- Direct REST call to `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}`
- System prompt sets context: "You are a cybersecurity expert assistant for the Tadamun security dashboard..."
- When user asks from **vulnerability detail page**, the vulnerability's CVE ID, CVSS score, and description are injected into the message context automatically
- Streaming not required; simple request/response JSON

Config additions to [`app/config.py`](app/config.py):
```python
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyD9kPcYLGADLVRkVuUPrhWH-OCm3r9A9wk")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
```

Note: Model name `gemini-3.1-flash-lite-preview` may not be available via the REST API yet; we'll use `gemini-2.0-flash-lite` as default and make it an env var so you can change it easily.

Add `requests` to `requirements.txt` (if not already there) — no large new dependency needed; we call Gemini via plain HTTP.

### 4. Nav + Vulnerability "Ask AI" Button

[`app/templates/base.html`](app/templates/base.html):
- Add "Attack Scenarios" under Security Tools dropdown
- Add "AI Assistant" nav link → `/ai-chat`

[`app/templates/vulnerabilities/detail.html`](app/templates/vulnerabilities/detail.html):
- Add "Ask AI about this vulnerability" button that opens chat with pre-filled context (CVE ID + description injected)

### 5. Register New Blueprint

[`app/__init__.py`](app/__init__.py):
- Register `ai_chat_bp` from `app/routes/ai_chat.py`

## Files Changed Summary

| File | Change |
|------|--------|
| `app/scanners/light_scanner.py` | **New** — pure-Python host discovery |
| `app/scanners/real_scanner.py` | Add nmap fallback to light_scanner |
| `app/routes/security_tools.py` | Add `/attack-scenarios` route |
| `app/templates/security_tools/attack_scenarios.html` | **New** — attack scenarios page |
| `app/routes/ai_chat.py` | **New** — Gemini chat blueprint |
| `app/templates/ai_chat/index.html` | **New** — chat UI |
| `app/config.py` | Add GEMINI_API_KEY, GEMINI_MODEL |
| `app/__init__.py` | Register ai_chat_bp |
| `app/templates/base.html` | Nav updates |
| `app/templates/vulnerabilities/detail.html` | Ask AI button |
| `requirements.txt` | Ensure `requests` is listed |
