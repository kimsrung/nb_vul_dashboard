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

    # Database: Supports PostgreSQL (asyncpg) or SQLite (aiosqlite)
    DATABASE_URL: str = "postgresql+asyncpg://qualys_user:qualys_secret_password@localhost:5432/qualys_alert_db"

    # Security / JWT
    SECRET_KEY: str = "qualys-risk-alert-super-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

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

    # MISP Threat Intelligence (FS-ISAC Feed) Configuration
    MISP_URL: str = "https://misp.internal.corp"
    MISP_API_KEY: str = ""
    MISP_CREATOR_ORG: str = "FS-ISAC"
    MISP_TAG_FILTER: str = "vulnerability:CVE%"
    MISP_FEED_TAG: str = "FS-ISAC"
    MISP_ENABLED: bool = True
    MISP_MOCK_MODE: bool = False  # Disabled by default; connects to live MISP server
    MISP_SYNC_INTERVAL_HOURS: int = 2
    MISP_WEBHOOK_SECRET: str = ""
    MISP_ZMQ_ENABLED: bool = False
    MISP_ZMQ_HOST: str = ""
    MISP_ZMQ_PORT: int = 50000

    # Risk Scoring Configuration
    RISK_THRESHOLD_CRITICAL: int = 80
    RISK_THRESHOLD_HIGH: int = 40
    SLA_CRITICAL_DAYS: int = 14
    SLA_HIGH_DAYS: int = 30


settings = Settings()
