from datetime import datetime
from app.extensions import db


class Incident(db.Model):
    __tablename__ = "incident"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(20), unique=True, nullable=False)  # INC-2026-0001
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False)   # critical / high / medium / low
    status = db.Column(db.String(30), nullable=False, default="new")  # new / investigating / contained / resolved
    assigned_to = db.Column(db.String(100))
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerability.id"), nullable=True)
    description = db.Column(db.Text)
    timeline_json = db.Column(db.Text)   # JSON array of {time, actor, action} events
    iocs_json = db.Column(db.Text)        # JSON array of {type, value, description}
    evidence_json = db.Column(db.Text)    # JSON array of {type, name, size, hash}
    recommended_actions = db.Column(db.Text)  # Plain text
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    device = db.relationship("Device", backref="incidents", lazy="joined")
    vulnerability = db.relationship("Vulnerability", backref="incidents", lazy="joined")

    def timeline(self):
        import json
        try:
            return json.loads(self.timeline_json or "[]")
        except Exception:
            return []

    def iocs(self):
        import json
        try:
            return json.loads(self.iocs_json or "[]")
        except Exception:
            return []

    def evidence(self):
        import json
        try:
            return json.loads(self.evidence_json or "[]")
        except Exception:
            return []
