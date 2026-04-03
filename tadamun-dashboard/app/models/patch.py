from datetime import datetime

from app.extensions import db


class Patch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=False)
    patch_name = db.Column(db.String(255), nullable=False)
    vendor = db.Column(db.String(120), nullable=False)
    release_date = db.Column(db.DateTime, nullable=True)
    urgency = db.Column(db.String(20), nullable=False, default="medium")
    recommendation = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    applied_date = db.Column(db.DateTime, nullable=True)
    vulnerability = db.relationship("Vulnerability", back_populates="patches")
