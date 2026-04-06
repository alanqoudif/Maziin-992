---
name: Tadamun Dashboard Phase 2 Implementation
overview: Enhance the Tadamun Dashboard with MITRE ATT&CK mapping, advanced scanner integration, SIEM logging, MFA, and interactive network topology visualization.
todos:
  - id: models-update
    content: Create MitreAttack and SecurityEvent models, update User model for MFA.
    status: completed
  - id: scanners-update
    content: Enhance Nmap, Wireshark, and Metasploit parsers.
    status: completed
  - id: data-generation
    content: Generate sample XML, CSV, and JSON data files.
    status: completed
  - id: seed-update
    content: Update seed_data.py with new models and mappings.
    status: completed
  - id: routes-setup
    content: Create routes for security tools and register them.
    status: completed
  - id: mfa-implementation
    content: Implement MFA setup and verification flow.
    status: completed
  - id: templates-development
    content: Develop templates for all new pages and update navbar.
    status: completed
  - id: finalization
    content: Finalize dashboard widgets and update requirements.txt.
    status: completed
isProject: false
---

I will implement the missing features and improvements for Phase 2 by following these steps:

1. **Update Database Schema**:
   - Create `[app/models/mitre.py](app/models/mitre.py)` with the `MitreAttack` model and many-to-many relationship with `Vulnerability`.
   - Update `[app/models/vulnerability.py](app/models/vulnerability.py)` to include the `mitre_techniques` relationship.
   - Create `[app/models/security_event.py](app/models/security_event.py)` with the `SecurityEvent` model for SIEM and IDS logs.
   - Update `[app/models/user.py](app/models/user.py)` to add `mfa_enabled` and `mfa_secret` fields for TOTP authentication.
   - Update `[app/models/device.py](app/models/device.py)` to include a relationship with `SecurityEvent`.

2. **Enhance Scanners and Sample Data**:
   - Update `[app/scanners/nmap_parser.py](app/scanners/nmap_parser.py)` with advanced parsing logic for OS detection, service versions, and NSE script results.
   - Update `[app/scanners/wireshark_parser.py](app/scanners/wireshark_parser.py)` to analyze CSV traffic captures for anomalies.
   - Update `[app/scanners/metasploit_parser.py](app/scanners/metasploit_parser.py)` to parse JSON exploit verification results.
   - Generate realistic sample data files in the `data/` directory: `[data/sample_nmap_scan.xml](data/sample_nmap_scan.xml)`, `[data/sample_pcap_analysis.csv](data/sample_pcap_analysis.csv)`, and `[data/sample_metasploit.json](data/sample_metasploit.json)`.

3. **Update Seed Logic**:
   - Modify `[seed_data.py](seed_data.py)` to:
     - Seed MITRE ATT&CK techniques and map them to vulnerabilities.
     - Generate SIEM security events and IDS/IPS logs.
     - Use the new parsers to populate `ScanResult` with realistic data.

4. **Implement New Routes and Templates**:
   - Create a new blueprint `[app/routes/security_tools.py](app/routes/security_tools.py)` for the new security tool pages.
   - Register the new blueprint in `[app/__init__.py](app/__init__.py)`.
   - Update `[app/templates/base.html](app/templates/base.html)` with the "Security Tools" dropdown navbar menu.
   - Build templates for:
     - `/scan-results/nmap`
     - `/traffic-analysis`
     - `/exploit-verification` (with confirmed exploitable flags)
     - `/network-topology` (interactive SVG/JS diagram)
     - `/siem-logs` (live feed and log views)
     - `/security-config` (encryption, firewall rules, RBAC)
   - Update `[app/templates/vulnerabilities/detail.html](app/templates/vulnerabilities/detail.html)` to include the MITRE section and matrix.

5. **Implement Multi-Factor Authentication (MFA)**:
   - Add MFA setup and verification logic to `[app/routes/auth.py](app/routes/auth.py)`.
   - Create MFA templates in `[app/templates/auth/](app/templates/auth/)`.
   - Update the login flow to support MFA challenges.

6. **Dashboard and Requirements**:
   - Update `[app/templates/dashboard/index.html](app/templates/dashboard/index.html)` with health status, MITRE coverage, and quick link cards.
   - Update `[requirements.txt](requirements.txt)` with `pyotp` and `qrcode[pil]`.
