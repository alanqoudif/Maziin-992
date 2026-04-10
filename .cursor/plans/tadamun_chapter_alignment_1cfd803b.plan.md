---
name: Tadamun Chapter Alignment
overview: Audit the existing Tadamun Flask project against Chapters 1–3 of the academic report, then build all 9 missing `/project/*` pages plus targeted updates to existing pages so every checklist item in the chapters is verifiable in the UI.
todos:
  - id: audit-md
    content: Create CHAPTER_AUDIT.md at project root mapping every checklist item to ✅/⚠️/❌
    status: pending
  - id: blueprint
    content: Create app/routes/project.py with all 9 @login_required routes and register in app/__init__.py
    status: pending
  - id: navbar
    content: "Update base.html: add Project dropdown (9 items) before Security Tools, update footer with Muscat/Vision 2040"
    status: pending
  - id: template-overview
    content: Create app/templates/project/overview.html — project identity, problem statement, scope, objectives, standards
    status: pending
  - id: template-stakeholders
    content: Create app/templates/project/stakeholders.html — 6-stakeholder table with Internal/External
    status: pending
  - id: template-methodology
    content: Create app/templates/project/methodology.html — PPDIOO stepper, SWOT grid, tool categories
    status: pending
  - id: template-literature
    content: Create app/templates/project/literature_review.html — 5 study cards, Research Gap table
    status: pending
  - id: template-feasibility
    content: Create app/templates/project/feasibility.html — 6 sections, 14-row cost table
    status: pending
  - id: template-planning
    content: Create app/templates/project/planning.html — schedule, WBS, Gantt, 4 planning tables
    status: pending
  - id: template-datacollection
    content: Create app/templates/project/data_collection.html — primary/secondary data, analysis methods
    status: pending
  - id: template-requirements
    content: Create app/templates/project/requirements.html — Table 3.6 with View in Dashboard buttons
    status: pending
  - id: template-toolscatalog
    content: Create app/templates/project/tools_catalog.html — 20+ tool cards with status badges
    status: pending
  - id: update-siem
    content: Update siem_logs.html — add IDS/Snort-style detection panel tab
    status: pending
  - id: update-nmap
    content: Update nmap_results.html — add OpenVAS simulated results section
    status: pending
  - id: update-secconfig
    content: Update security_config.html — explicit Cisco ASA, TLS 1.3, AES-256, VPN, Palo Alto labels
    status: pending
  - id: update-compliance
    content: Verify/update compliance/index.html — ISO 27001, NIST CSF 2.0, CIS v8, MITRE ATT&CK v14
    status: pending
isProject: false
---

# Tadamun Dashboard — Chapter Alignment Plan

## Audit Summary

### Already Implemented ✅

- Project named "SOC dashboard" (`base.html` title + header brand)
- MFA route `/auth/setup-mfa` exists
- `/scan-results/nmap`, `/traffic-analysis`, `/exploit-verification`, `/network-topology`, `/siem-logs`, `/security-config` all exist
- AI model (Scikit-learn Random Forest) — `app/ai/`
- SQLite database, Flask framework, seed data with ~200 devices
- MITRE ATT&CK model (`app/models/mitre.py`), used in vuln detail
- Compliance page (`/compliance/`) exists (standards need verifying)
- Chart.js loaded in `base.html`

### Not Implemented ❌ (all `/project/*` pages)

- `/project/overview`, `/project/stakeholders`, `/project/methodology`
- `/project/literature-review`, `/project/feasibility`, `/project/planning`
- `/project/data-collection`, `/project/requirements`, `/project/tools-catalog`
- "Project" dropdown in navbar
- `CHAPTER_AUDIT.md`

### Partially Implemented ⚠️ (existing pages needing updates)

- `siem_logs.html` — no dedicated Snort/Suricata IDS panel
- `nmap_results.html` — no OpenVAS tab/reference
- `security_config.html` — needs explicit Cisco ASA, TLS 1.3, AES-256, VPN mentions
- `base.html` footer — no "Muscat, Oman / Oman Vision 2040" reference
- `compliance/index.html` — needs ISO 27001, NIST CSF 2.0, CIS Controls v8, MITRE ATT&CK v14 explicitly listed

---

## Files to Create

### 1. `app/routes/project.py`

New blueprint `project_bp` with `url_prefix="/project"`, all routes `@login_required`:

```python
@project_bp.route("/overview")
@project_bp.route("/stakeholders")
@project_bp.route("/methodology")
@project_bp.route("/literature-review")
@project_bp.route("/feasibility")
@project_bp.route("/planning")
@project_bp.route("/data-collection")
@project_bp.route("/requirements")
@project_bp.route("/tools-catalog")
```

Each route passes only static context (no DB queries needed — all content is from chapters).

### 2. `app/templates/project/` — 9 templates

All extend `base.html`, use existing dark-theme Tailwind classes (`bg-card`, `text-muted-foreground`, `border`, etc.).


| Template                 | Key Content                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `overview.html`          | Project identity, problem statement, scope, Oman Vision 2040, budget 4,000–4,400 OMR                                |
| `stakeholders.html`      | 6-stakeholder table with Internal/External classification                                                           |
| `methodology.html`       | PPDIOO 6-stage horizontal flow (CSS), SWOT 2×2 grid, "Why PPDIOO?"                                                  |
| `literature_review.html` | 5 study cards + Research Gap Summary table                                                                          |
| `feasibility.html`       | 6 sections (Technical/Economic/Operational/Functional/Scheduling/Social), 14-row cost table                         |
| `planning.html`          | Schedule table, WBS tree (SVG/CSS), Gantt (Chart.js), 4 planning tables (Resource, Communication, Risk, Acceptance) |
| `data_collection.html`   | Primary/secondary methods, analysis methods, findings, interpretation                                               |
| `requirements.html`      | Table 3.6 (14 rows) with "View in Dashboard" buttons linking to existing routes                                     |
| `tools_catalog.html`     | 20+ tool cards with category, chapter reference, status badge, "Open" button                                        |


### 3. `CHAPTER_AUDIT.md`

Root-level file mapping every checklist item to ✅/⚠️/❌ with file references.

---

## Files to Modify

### `app/__init__.py`

Add 2 lines:

```python
from app.routes.project import project_bp
app.register_blueprint(project_bp)
```

### `app/templates/base.html`

Insert "Project ▼" dropdown **before** "Security Tools ▼" using the same `group-hover` pattern (lines 83–97). Footer: add "Muscat, Oman | Oman Vision 2040" to the copyright line.

### `app/templates/security_tools/siem_logs.html`

Add a tabbed "IDS/IPS Detection Logs" panel showing Snort/Suricata-style simulated alerts with a "Simulated IDS (Snort-style)" badge.

### `app/templates/security_tools/nmap_results.html`

Add an "OpenVAS" tab/section clearly labeled "Simulated OpenVAS Scan Results" with a few mock findings.

### `app/templates/security_tools/security_config.html`

Verify/add explicit labels for: Cisco ASA, AES-256, TLS 1.3, VPN, Palo Alto, GNS3 simulation reference.

### `app/templates/compliance/index.html`

Verify/add all 4 standards: ISO/IEC 27001, NIST CSF 2.0, CIS Controls v8, MITRE ATT&CK v14.

---

## Page-by-Page Content Details

### `/project/overview`

- Project name, student (Mazin Mohamed AlMuqaimi, MEC 10F6731), supervisor
- Problem statement bullets (manual scanning, CVSS-only, alert fatigue, business impact refs)
- Scope: 200 devices, on-premises LAN, not cloud, no zero-day prediction, 6-month, ~4,000–4,400 OMR
- Standards alignment table: ISO 27001, NIST CSF 2.0, CIS v8, MITRE ATT&CK v14
- Objectives 1–5 as a numbered list
- Footer: "Based on Chapter 1, Sections 1.1–1.5"

### `/project/methodology`

- PPDIOO horizontal stepper (CSS `flex` with numbered circles + connecting lines)
- Each stage expands on click (JS toggle) with description from Ch 3.4
- SWOT grid (2×2, colored quadrants with dark-theme opacity)
- "Why PPDIOO?" paragraph from Ch 3.3.1
- Operate stage explicitly lists: SIEM, IDS/IPS, NSTMT, VAPTT, ESTHT, DFIR, IAM, TI/OSINT as "integrated/simulated" chips
- Footer: "Based on Chapter 3, Sections 3.2–3.4"

### `/project/feasibility`

- 6 collapsible accordion sections
- Economic section has full 14-row styled table with OMR amounts and ~4,000 OMR total row
- Technical section lists every tool with status chip (Available / Configured / Free)

### `/project/planning`

- Schedule table: 4 phases, Oct 2025–Jan 2026 dates
- WBS: CSS tree diagram (nested `<ul>` styled as tree)
- Gantt: Chart.js horizontal bar chart with phases mapped to date ranges
- 4 tables: Resource Plan, Communication Plan, Risk (R1–R5), Acceptance Criteria

### `/project/requirements` (Table 3.6)

- 14-row interactive table, each row has "View in Dashboard" button:
  - RBAC → `/security-config`
  - MFA → `/auth/setup-mfa`
  - Nmap → `/scan-results/nmap`
  - Wireshark → `/traffic-analysis`
  - Metasploit → `/exploit-verification`
  - SIEM (Splunk) → `/siem-logs`
  - Firewall → `/security-config`
  - Encryption (AES-256 / TLS 1.3) → `/security-config`
  - SSH/VPN → `/security-config`

### `/project/tools-catalog`

- Card grid for 20+ tools
- Each card: tool name, category badge, "Mentioned in Ch X.X", integration status (✅/⚠️/📋), "Open" button
- Status key legend at top

---

## Execution Order

1. Create `CHAPTER_AUDIT.md`
2. Create `app/routes/project.py`
3. Register blueprint in `app/__init__.py`
4. Update `base.html` (navbar + footer)
5. Create all 9 templates in `app/templates/project/`
6. Update `siem_logs.html` (IDS panel)
7. Update `nmap_results.html` (OpenVAS section)
8. Update `security_config.html` (explicit tool/protocol labels)
9. Verify `compliance/index.html` standards list

