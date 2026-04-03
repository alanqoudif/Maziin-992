from datetime import datetime

from app.extensions import db


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(120), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    mac_address = db.Column(db.String(32), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    os = db.Column(db.String(120), nullable=False)
    os_version = db.Column(db.String(120), nullable=True)
    department = db.Column(db.String(120), nullable=False)
    vlan = db.Column(db.String(20), nullable=False)
    subnet = db.Column(db.String(32), nullable=False)
    role = db.Column(db.String(120), nullable=False)
    criticality = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="active")
    last_scan = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scan_results = db.relationship("ScanResult", back_populates="device", lazy=True)
    alerts = db.relationship("Alert", back_populates="device", lazy=True)
