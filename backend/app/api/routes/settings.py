from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import require_admin, require_viewer
from app.models.user import User
from app.schemas.settings import (
    SystemSettingsResponse,
    SystemSettingsUpdate,
    QualysTestRequest,
    TelegramTestRequest,
)
from app.services.qualys_client import QualysApiClient
from app.services.telegram_service import TelegramService

router = APIRouter(prefix="/settings", tags=["Settings"])


def _mask_token(token: str) -> str:
    if not token or len(token) < 8:
        return "Not Set"
    return token[:4] + "..." + token[-4:]


@router.get("", response_model=SystemSettingsResponse)
async def get_settings(user: User = Depends(require_viewer)):
    return SystemSettingsResponse(
        qualys_api_url=settings.QUALYS_API_URL,
        qualys_username=settings.QUALYS_USERNAME,
        qualys_mock_mode=settings.QUALYS_MOCK_MODE,
        qualys_sync_interval_hours=settings.QUALYS_SYNC_INTERVAL_HOURS,
        qualys_tag_filter=settings.QUALYS_TAG_FILTER,
        telegram_enabled=settings.TELEGRAM_ENABLED,
        telegram_bot_token_masked=_mask_token(settings.TELEGRAM_BOT_TOKEN),
        telegram_chat_id=settings.TELEGRAM_CHAT_ID,
        telegram_cooldown_hours=settings.TELEGRAM_COOLDOWN_HOURS,
        risk_threshold_critical=settings.RISK_THRESHOLD_CRITICAL,
        risk_threshold_high=settings.RISK_THRESHOLD_HIGH,
        sla_critical_days=settings.SLA_CRITICAL_DAYS,
        sla_high_days=settings.SLA_HIGH_DAYS,
    )


@router.post("", response_model=SystemSettingsResponse)
async def update_settings(
    settings_in: SystemSettingsUpdate,
    admin: User = Depends(require_admin),
):
    if settings_in.qualys_api_url is not None:
        settings.QUALYS_API_URL = settings_in.qualys_api_url
    if settings_in.qualys_username is not None:
        settings.QUALYS_USERNAME = settings_in.qualys_username
    if settings_in.qualys_password is not None and settings_in.qualys_password.strip():
        settings.QUALYS_PASSWORD = settings_in.qualys_password
    if settings_in.qualys_mock_mode is not None:
        settings.QUALYS_MOCK_MODE = settings_in.qualys_mock_mode
    if settings_in.qualys_sync_interval_hours is not None:
        settings.QUALYS_SYNC_INTERVAL_HOURS = settings_in.qualys_sync_interval_hours
    if settings_in.qualys_tag_filter is not None:
        settings.QUALYS_TAG_FILTER = settings_in.qualys_tag_filter

    if settings_in.telegram_enabled is not None:
        settings.TELEGRAM_ENABLED = settings_in.telegram_enabled
    if settings_in.telegram_bot_token is not None and settings_in.telegram_bot_token.strip():
        settings.TELEGRAM_BOT_TOKEN = settings_in.telegram_bot_token
    if settings_in.telegram_chat_id is not None:
        settings.TELEGRAM_CHAT_ID = settings_in.telegram_chat_id
    if settings_in.telegram_cooldown_hours is not None:
        settings.TELEGRAM_COOLDOWN_HOURS = settings_in.telegram_cooldown_hours

    if settings_in.risk_threshold_critical is not None:
        settings.RISK_THRESHOLD_CRITICAL = settings_in.risk_threshold_critical
    if settings_in.risk_threshold_high is not None:
        settings.RISK_THRESHOLD_HIGH = settings_in.risk_threshold_high
    if settings_in.sla_critical_days is not None:
        settings.SLA_CRITICAL_DAYS = settings_in.sla_critical_days
    if settings_in.sla_high_days is not None:
        settings.SLA_HIGH_DAYS = settings_in.sla_high_days

    return SystemSettingsResponse(
        qualys_api_url=settings.QUALYS_API_URL,
        qualys_username=settings.QUALYS_USERNAME,
        qualys_mock_mode=settings.QUALYS_MOCK_MODE,
        qualys_sync_interval_hours=settings.QUALYS_SYNC_INTERVAL_HOURS,
        qualys_tag_filter=settings.QUALYS_TAG_FILTER,
        telegram_enabled=settings.TELEGRAM_ENABLED,
        telegram_bot_token_masked=_mask_token(settings.TELEGRAM_BOT_TOKEN),
        telegram_chat_id=settings.TELEGRAM_CHAT_ID,
        telegram_cooldown_hours=settings.TELEGRAM_COOLDOWN_HOURS,
        risk_threshold_critical=settings.RISK_THRESHOLD_CRITICAL,
        risk_threshold_high=settings.RISK_THRESHOLD_HIGH,
        sla_critical_days=settings.SLA_CRITICAL_DAYS,
        sla_high_days=settings.SLA_HIGH_DAYS,
    )


@router.post("/test-qualys")
async def test_qualys_connection(
    test_req: QualysTestRequest,
    admin: User = Depends(require_admin),
):
    client = QualysApiClient(
        base_url=test_req.qualys_api_url,
        username=test_req.qualys_username,
        password=test_req.qualys_password,
        mock_mode=test_req.qualys_mock_mode,
    )
    result = await client.test_connection()
    return result


@router.post("/test-telegram")
async def test_telegram_connection(
    test_req: TelegramTestRequest,
    admin: User = Depends(require_admin),
):
    token = test_req.bot_token or settings.TELEGRAM_BOT_TOKEN
    cid = test_req.chat_id or settings.TELEGRAM_CHAT_ID

    if not token or not cid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Telegram Bot Token and Chat ID must be specified",
        )

    msg = "🛡 <b>Qualys Risk Alert Dashboard: Test Alert</b>\n\n✅ Your Telegram Bot integration is configured correctly!"
    result = await TelegramService.send_message(msg, bot_token=token, chat_id=cid)
    return result
