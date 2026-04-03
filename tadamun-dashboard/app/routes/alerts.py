from flask import Blueprint, render_template
from flask_login import login_required

from app.models.alert import Alert
from app.routes.rbac import roles_required

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/")
@login_required
@roles_required("admin", "security_analyst")
def list_alerts():
    alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    return render_template("alerts/list.html", alerts=alerts)
