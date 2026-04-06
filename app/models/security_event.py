from datetime import datetime
from app.extensions import db

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50))       # "Firewall", "IDS/IPS", "SIEM", "Endpoint"
    event_type = db.Column(db.String(100))   # "Intrusion Attempt", "Login Failure", "Policy Violation"
    severity = db.Column(db.String(20))      # critical, high, medium, low, info
    source_ip = db.Column(db.String(50))
    dest_ip = db.Column(db.String(50))
    message = db.Column(db.Text)
    raw_log = db.Column(db.Text)             # Simulated raw syslog/CEF format
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))

    device = db.relationship("Device", back_populates="security_events")
