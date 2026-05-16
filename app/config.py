import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_INSTANCE_DIR = _PROJECT_ROOT / "instance"
_DEFAULT_SQLITE = _INSTANCE_DIR / "tadamun.db"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Always resolve SQLite to project/instance (avoids empty cwd-relative DB files with no tables)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{_DEFAULT_SQLITE.as_posix()}",
    )
    SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    REAL_SCAN_ENABLED = os.getenv("REAL_SCAN_ENABLED", "true").lower() in {"1", "true", "yes"}
    SCAN_ALLOWED_CIDRS = os.getenv("SCAN_ALLOWED_CIDRS", "192.168.0.0/16")
    SCAN_DEFAULT_PROFILE = os.getenv("SCAN_DEFAULT_PROFILE", "-sV -Pn --open")
    NMAP_BINARY_PATH = os.getenv("NMAP_BINARY_PATH", "nmap")
    SCAN_TIMEOUT_SEC = int(os.getenv("SCAN_TIMEOUT_SEC", "120"))
    SCAN_MAX_TARGETS = int(os.getenv("SCAN_MAX_TARGETS", "16"))
    SCAN_FALLBACK_PROFILE = os.getenv("SCAN_FALLBACK_PROFILE", "-sn")
    AUTO_SCAN_ON_START = os.getenv("AUTO_SCAN_ON_START", "true").lower() in {"1", "true", "yes"}
    AUTO_SCAN_INTERVAL_SEC = int(os.getenv("AUTO_SCAN_INTERVAL_SEC", "300"))
    # Gemini AI Assistant
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyD9kPcYLGADLVRkVuUPrhWH-OCm3r9A9wk")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
