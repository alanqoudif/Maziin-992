from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.models.user import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.before_app_request
def enforce_session_timeout():
    if not current_user.is_authenticated:
        return
    now = datetime.utcnow().timestamp()
    last_seen = session.get("last_seen", now)
    timeout_seconds = int(session.get("timeout_seconds", 30 * 60))
    if now - last_seen > timeout_seconds:
        logout_user()
        flash("Session timed out due to inactivity.", "warning")
        return redirect(url_for("auth.login"))
    session["last_seen"] = now


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            session.permanent = True
            session["last_seen"] = datetime.utcnow().timestamp()
            session["timeout_seconds"] = 30 * 60
            return redirect(url_for("dashboard.index"))
        flash("Invalid credentials.", "danger")
    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
@login_required
def register():
    if current_user.role != "admin":
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        user = User(
            username=request.form["username"].strip(),
            email=request.form["email"].strip(),
            role=request.form.get("role", "viewer"),
            mfa_enabled=bool(request.form.get("mfa_enabled")),
        )
        user.set_password(request.form["password"])
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
