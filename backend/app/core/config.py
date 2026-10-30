from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_ROOT_DIR = _BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(
            str(_ROOT_DIR / ".env"),
            str(_BACKEND_DIR / ".env"),
            ".env",
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PROJECT_NAME: str = "Risk Alert Dashboard"
    API_V1_STR: str = "/api/v1"

    # Database: PostgreSQL (asyncpg)
    DATABASE_URL: str = "postgresql+asyncpg://risk_alert_user:risk_alert_secret_password@localhost:5432/risk_alert_db"

    # Security / JWT & CORS
    SECRET_KEY: str = "qualys-risk-alert-super-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"

    # Default Seed Users
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"
    ADMIN_EMAIL: str = "admin@internal.security"

    VIEWER_USERNAME: str = "viewer"
    VIEWER_PASSWORD: str = "viewer123"
    VIEWER_EMAIL: str = "viewer@internal.security"

    # Qualys API Configuration
    QUALYS_API_URL: str = "https://qualysapi.qualys.com"
    QUALYS_USERNAME: str = ""
    QUALYS_PASSWORD: str = ""
    QUALYS_MOCK_MODE: bool = False  # Disabled by default; connects to real Qualys API
    QUALYS_SYNC_INTERVAL_HOURS: int = 6
    QUALYS_TAG_FILTER: str = ""

    # Telegram Alert Configuration
    TELEGRAM_ENABLED: bool = False
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    TELEGRAM_COOLDOWN_HOURS: int = 6

    # MISP Threat Intelligence (FS-ISAC / CIRCL Feed) Configuration
    MISP_URL: str = "https://misp.internal.corp"
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True
    MISP_CREATOR_ORG: str = "FS-ISAC"  # "FS-ISAC" for production, "CIRCL" for local testing, or "*" for all orgs
    MISP_TAG_FILTER: str = "vulnerability:CVE%, cve"  # Comma-separated tag filters for focused CVE taxonomy, or empty for all events
    MISP_FEED_TAG: str = "FS-ISAC"
    MISP_ENABLED: bool = True
    MISP_MOCK_MODE: bool = False  # Disabled by default; connects to live MISP server
    MISP_SYNC_INTERVAL_HOURS: int = 0  # 0 = Scheduled sync disabled; relies on real-time ZeroMQ stream + manual UI trigger
    MISP_ZMQ_ENABLED: bool = False
    MISP_ZMQ_HOST: str = ""
    MISP_ZMQ_PORT: int = 50000
    MISP_ZMQ_USERNAME: str = ""
    MISP_ZMQ_PASSWORD: str = ""

    # API Documentation Credentials (HTTP Basic Auth for /docs and /openapi.json)
    DOCS_USERNAME: str = "docs_admin"
    DOCS_PASSWORD: str = "docs123"



settings = Settings()
