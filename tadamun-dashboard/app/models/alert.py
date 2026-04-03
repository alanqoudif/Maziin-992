from datetime import datetime

from app.extensions import db


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    device = db.relationship("Device", back_populates="alerts")
    vulnerability = db.relationship("Vulnerability", back_populates="alerts")
