from flask import Blueprint, render_template
from flask_login import login_required

from app.models.patch import Patch
from app.routes.rbac import roles_required

patches_bp = Blueprint("patches", __name__, url_prefix="/patches")


@patches_bp.route("/")
@login_required
@roles_required("admin", "network_admin")
def list_patches():
    patches = Patch.query.order_by(Patch.status, Patch.urgency.desc()).all()
    return render_template("patches/list.html", patches=patches)
