from app import create_app
from app.extensions import db
from app.models.user import User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REAL_SCAN_ENABLED = True
    SCAN_ALLOWED_CIDRS = "192.168.1.0/24"
    SCAN_MAX_TARGETS = 2
    SCAN_DEFAULT_PROFILE = "-sV -Pn --open"


def _bootstrap_user():
    user = User(username="admin", email="admin@example.com", role="admin")
    user.set_password("admin")
    db.session.add(user)
    db.session.commit()


def _login(client):
    client.post("/auth/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)


def test_trigger_scan_rejects_outside_allowlist(monkeypatch):
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        _bootstrap_user()
    client = app.test_client()
    _login(client)
    response = client.post("/api/v1/scan/trigger", json={"targets": ["10.1.1.0/24"], "real": True})
    assert response.status_code == 400
    assert "outside allowed CIDRs" in response.get_json()["message"]


def test_trigger_scan_accepts_valid_target(monkeypatch):
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        _bootstrap_user()

    called = {}

    def fake_start(targets, profile):
        called["targets"] = targets
        called["profile"] = profile

    monkeypatch.setattr("app.routes.api.start_scan_job", fake_start)
    client = app.test_client()
    _login(client)
    response = client.post("/api/v1/scan/trigger", json={"targets": ["192.168.1.0/24"], "real": True})
    assert response.status_code == 200
    assert response.get_json()["status"] == "accepted"
    assert called["targets"] == ["192.168.1.0/24"]
