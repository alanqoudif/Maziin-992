from datetime import datetime
from app.extensions import db


class EndpointAgent(db.Model):
    __tablename__ = "endpoint_agent"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    agent_version = db.Column(db.String(20), default="5.3.1")
    status = db.Column(db.String(20), default="online")   # online / offline / error / isolated
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    threats_detected = db.Column(db.Integer, default=0)
    isolated = db.Column(db.Boolean, default=False)
    threats_json = db.Column(db.Text)       # JSON list of detected threat objects
    hunt_results_json = db.Column(db.Text)  # JSON list of hunt query result objects
    process_tree_json = db.Column(db.Text)  # JSON nested tree for compromised host

    device = db.relationship("Device", backref="endpoint_agent", lazy="joined", uselist=False)

    def threats(self):
        import json
        try:
            return json.loads(self.threats_json or "[]")
        except Exception:
            return []

    def process_tree(self):
        import json
        try:
            return json.loads(self.process_tree_json or "null")
        except Exception:
            return None
