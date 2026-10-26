from typing import Optional
from pydantic import BaseModel


class SystemSettingsResponse(BaseModel):
    qualys_api_url: str
    qualys_username: str
    qualys_mock_mode: bool
    qualys_sync_interval_hours: int
    qualys_tag_filter: str
    
    misp_url: str
    misp_api_key_masked: str
    misp_creator_org: str = "FS-ISAC"
    misp_tag_filter: str = "vulnerability:CVE%"
    misp_feed_tag: str
    misp_enabled: bool
    misp_mock_mode: bool
    misp_sync_interval_hours: int
    misp_zmq_enabled: bool = False
    misp_zmq_host: str = ""
    misp_zmq_port: int = 50000
    misp_zmq_username: Optional[str] = None
    misp_zmq_password_masked: Optional[str] = None

    telegram_enabled: bool
    telegram_bot_token_masked: str
    telegram_chat_id: str
    telegram_cooldown_hours: int

    docs_username: str = "docs_admin"
    docs_password_masked: str = "••••••••"


class SystemSettingsUpdate(BaseModel):
    qualys_api_url: Optional[str] = None
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_mock_mode: Optional[bool] = None
    qualys_sync_interval_hours: Optional[int] = None
    qualys_tag_filter: Optional[str] = None
    
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_creator_org: Optional[str] = None
    misp_tag_filter: Optional[str] = None
    misp_feed_tag: Optional[str] = None
    misp_enabled: Optional[bool] = None
    misp_mock_mode: Optional[bool] = None
    misp_sync_interval_hours: Optional[int] = None
    misp_zmq_enabled: Optional[bool] = None
    misp_zmq_host: Optional[str] = None
    misp_zmq_port: Optional[int] = None
    misp_zmq_username: Optional[str] = None
    misp_zmq_password: Optional[str] = None

    telegram_enabled: Optional[bool] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_cooldown_hours: Optional[int] = None

    docs_username: Optional[str] = None
    docs_password: Optional[str] = None


class QualysTestRequest(BaseModel):
    qualys_api_url: Optional[str] = None
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_mock_mode: Optional[bool] = None


class MispTestRequest(BaseModel):
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_creator_org: Optional[str] = None
    misp_tag_filter: Optional[str] = None
    misp_feed_tag: Optional[str] = None
    misp_mock_mode: Optional[bool] = None
    misp_zmq_enabled: Optional[bool] = None
    misp_zmq_host: Optional[str] = None
    misp_zmq_port: Optional[int] = None
    misp_zmq_username: Optional[str] = None
    misp_zmq_password: Optional[str] = None


class TelegramTestRequest(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
