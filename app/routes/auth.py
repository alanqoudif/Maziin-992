from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for, current_app
from flask_login import current_user, login_required, login_user, logout_user
import pyotp
import qrcode
import io
import base64

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
            if user.mfa_enabled:
                session["mfa_user_id"] = user.id
                return redirect(url_for("auth.verify_mfa"))
            
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

@auth_bp.route("/setup-mfa", methods=["GET", "POST"])
@login_required
def setup_mfa():
    if request.method == "POST":
        code = request.form.get("code")
        secret = session.get("mfa_secret")
        if pyotp.TOTP(secret).verify(code):
            current_user.mfa_secret = secret
            current_user.mfa_enabled = True
            db.session.commit()
            flash("MFA has been enabled successfully.", "success")
            return redirect(url_for("dashboard.index"))
        else:
            flash("Invalid verification code. Please try again.", "danger")

    # Generate secret
    secret = pyotp.random_base32()
    session["mfa_secret"] = secret
    
    # Generate QR Code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name="SOC Dashboard")
    
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf)
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode()
    
    return render_template("auth/setup_mfa.html", secret=secret, qr_code=qr_code_base64)

@auth_bp.route("/verify-mfa", methods=["GET", "POST"])
def verify_mfa():
    user_id = session.get("mfa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("auth.login"))
        
    if request.method == "POST":
        code = request.form.get("code")
        if pyotp.TOTP(user.mfa_secret).verify(code):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            session.pop("mfa_user_id", None)
            session.permanent = True
            session["last_seen"] = datetime.utcnow().timestamp()
            session["timeout_seconds"] = 30 * 60
            return redirect(url_for("dashboard.index"))
        else:
            flash("Invalid MFA code.", "danger")
            
    return render_template("auth/verify_mfa.html")
