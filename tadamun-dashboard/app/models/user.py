from datetime import datetime
from enum import Enum

import bcrypt
from flask_login import UserMixin

from app.extensions import db, login_manager


class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    NETWORK_ADMIN = "network_admin"
    VIEWER = "viewer"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default=UserRole.VIEWER.value)
    mfa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
