from io import BytesIO

from flask import Blueprint, Response, render_template, request
from flask_login import login_required
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from app.models.alert import Alert
from app.models.device import Device
from app.models.patch import Patch
from app.models.vulnerability import Vulnerability

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@login_required
def index():
    return render_template("reports/index.html")


@reports_bp.route("/executive.pdf")
@login_required
def executive_report():
    report_type = request.args.get("type", "executive")
    date_from = request.args.get("date_from", "N/A")
    date_to = request.args.get("date_to", "N/A")

    total_devices = Device.query.count()
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity="critical").count()
    total_alerts = Alert.query.count()
    pending_patches = Patch.query.filter(Patch.status.in_(["pending", "failed"])).count()

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle(f"Vulnerability Prioritization {report_type.title()} Security Report")
    pdf.drawString(72, 800, f"Enterprise Security Lab — {report_type.title()} Security Report")
    pdf.drawString(72, 780, f"Date Scope: {date_from} to {date_to}")
    pdf.drawString(72, 755, f"Total Devices: {total_devices}")
    pdf.drawString(72, 740, f"Total Vulnerabilities: {total_vulns}")
    pdf.drawString(72, 725, f"Critical Vulnerabilities: {critical_vulns}")
    pdf.drawString(72, 710, f"Total Alerts: {total_alerts}")
    pdf.drawString(72, 695, f"Pending/Failed Patches: {pending_patches}")
    if report_type == "compliance":
        pdf.drawString(72, 670, "Compliance Focus: Include control evidence and open gaps.")
    elif report_type == "vulnerability":
        pdf.drawString(72, 670, "Vulnerability Focus: Prioritize exploitable and externally exposed CVEs.")
    else:
        pdf.drawString(72, 670, "Executive Focus: High-level risk posture and operational readiness.")
    pdf.showPage()
    pdf.save()
    return Response(buffer.getvalue(), mimetype="application/pdf")
