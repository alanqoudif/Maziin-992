from app.extensions import db

vuln_mitre = db.Table('vuln_mitre',
    db.Column('vulnerability_id', db.Integer, db.ForeignKey('vulnerability.id'), primary_key=True),
    db.Column('mitre_id', db.Integer, db.ForeignKey('mitre_attack.id'), primary_key=True)
)

class MitreAttack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(20), unique=True, nullable=False)  # e.g., "T1190"
    technique_name = db.Column(db.String(200), nullable=False)              # e.g., "Exploit Public-Facing Application"
    tactic = db.Column(db.String(100), nullable=False)                      # e.g., "Initial Access"
    description = db.Column(db.Text)
    url = db.Column(db.String(300))                                         # Link to attack.mitre.org

    vulnerabilities = db.relationship("Vulnerability", secondary=vuln_mitre, back_populates="mitre_techniques")
