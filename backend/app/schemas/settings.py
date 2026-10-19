from typing import Optional
from pydantic import BaseModel


class SystemSettingsResponse(BaseModel):
    qualys_api_url: str
    qualys_username: str
    qualys_mock_mode: bool
    qualys_sync_interval_hours: int
    qualys_tag_filter: str
    
    telegram_enabled: bool
    telegram_bot_token_masked: str
    telegram_chat_id: str
    telegram_cooldown_hours: int
    
    risk_threshold_critical: int
    risk_threshold_high: int
    sla_critical_days: int
    sla_high_days: int


class SystemSettingsUpdate(BaseModel):
    qualys_api_url: Optional[str] = None
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_mock_mode: Optional[bool] = None
    qualys_sync_interval_hours: Optional[int] = None
    qualys_tag_filter: Optional[str] = None
    
    telegram_enabled: Optional[bool] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_cooldown_hours: Optional[int] = None
    
    risk_threshold_critical: Optional[int] = None
    risk_threshold_high: Optional[int] = None
    sla_critical_days: Optional[int] = None
    sla_high_days: Optional[int] = None


class QualysTestRequest(BaseModel):
    qualys_api_url: Optional[str] = None
    qualys_username: Optional[str] = None
    qualys_password: Optional[str] = None
    qualys_mock_mode: Optional[bool] = None


class TelegramTestRequest(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
