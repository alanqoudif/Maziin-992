from app import create_app
from app.extensions import db
from app.models.user import User


class TestConfig:
    TESTING = True
    SECRET_KEY = "test"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def bootstrap_user():
    u = User(username="admin", email="a@a.com", role="admin")
    u.set_password("admin")
    db.session.add(u)
    db.session.commit()


def test_login_route():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        bootstrap_user()
    client = app.test_client()
    response = client.post("/auth/login", data={"username": "admin", "password": "admin"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security Operations Dashboard" in response.data
