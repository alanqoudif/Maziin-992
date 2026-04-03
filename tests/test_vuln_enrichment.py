from app import create_app
from app.extensions import db
from app.models.device import Device
from app.scanners.vuln_enrichment import enrich_device_vulnerabilities


class TestConfig:
    TESTING = True
    SECRET_KEY = "test"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def test_enrichment_generates_vulnerability_entities():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        device = Device(
            hostname="DISC-10",
            ip_address="192.168.1.10",
            mac_address="00:00:00:00:00:00",
            device_type="server",
            os="Unknown",
            os_version=None,
            department="Discovered Network",
            vlan="Unknown",
            subnet="192.168.1.0/24",
            role="discovered endpoint",
            criticality="medium",
            status="active",
        )
        db.session.add(device)
        rows = list(enrich_device_vulnerabilities(device, [{"port": 22, "service": "ssh", "state": "open"}]))
        assert any(kind == "vulnerability" for kind, _ in rows)
