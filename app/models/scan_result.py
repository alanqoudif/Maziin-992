from datetime import datetime

from app.extensions import db


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(30), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    parsed_results = db.Column(db.JSON, nullable=True)
    findings_count = db.Column(db.Integer, default=0)

    device = db.relationship("Device", back_populates="scan_results")
