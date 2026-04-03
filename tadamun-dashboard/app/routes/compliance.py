from flask import Blueprint, render_template
from flask_login import login_required

compliance_bp = Blueprint("compliance", __name__, url_prefix="/compliance")

FRAMEWORKS = [
    {
        "key": "iso27001",
        "title": "ISO/IEC 27001",
        "weight": 0.4,
        "controls": [
            {"name": "Asset inventory and ownership", "done": 18, "total": 20},
            {"name": "Access control enforcement", "done": 16, "total": 20},
            {"name": "Logging and monitoring evidence", "done": 13, "total": 15},
            {"name": "Patch governance and SLAs", "done": 10, "total": 12},
            {"name": "Incident response readiness", "done": 9, "total": 12},
        ],
    },
    {
        "key": "nist_csf",
        "title": "NIST CSF",
        "weight": 0.35,
        "controls": [
            {"name": "Identify function controls", "done": 15, "total": 20},
            {"name": "Protect function controls", "done": 17, "total": 24},
            {"name": "Detect function controls", "done": 14, "total": 18},
            {"name": "Respond function controls", "done": 12, "total": 18},
            {"name": "Recover function controls", "done": 11, "total": 16},
        ],
    },
    {
        "key": "cis_controls_v8",
        "title": "CIS Controls v8",
        "weight": 0.25,
        "controls": [
            {"name": "Inventory and control of assets", "done": 14, "total": 18},
            {"name": "Secure configuration management", "done": 12, "total": 18},
            {"name": "Continuous vulnerability management", "done": 11, "total": 16},
            {"name": "Account management", "done": 9, "total": 14},
            {"name": "Audit log management", "done": 8, "total": 12},
        ],
    },
]


def _compute_framework_scores():
    frameworks = []
    weighted_total = 0.0
    weight_sum = 0.0
    for fw in FRAMEWORKS:
        total_controls = sum(c["total"] for c in fw["controls"])
        done_controls = sum(c["done"] for c in fw["controls"])
        score = round((done_controls / total_controls) * 100) if total_controls else 0
        frameworks.append(
            {
                "key": fw["key"],
                "title": fw["title"],
                "weight": fw["weight"],
                "score": score,
                "done_controls": done_controls,
                "total_controls": total_controls,
                "controls": fw["controls"],
            }
        )
        weighted_total += score * fw["weight"]
        weight_sum += fw["weight"]
    overall = round(weighted_total / weight_sum) if weight_sum else 0
    return frameworks, overall


@compliance_bp.route("/")
@login_required
def index():
    frameworks, overall = _compute_framework_scores()
    return render_template("compliance/index.html", frameworks=frameworks, overall=overall)
