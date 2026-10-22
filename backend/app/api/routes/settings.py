from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.api.deps import require_admin, require_viewer
from app.models.user import User
from app.models.setting import SystemSetting
from app.schemas.settings import (
    SystemSettingsResponse,
    SystemSettingsUpdate,
    QualysTestRequest,
    MispTestRequest,
    TelegramTestRequest,
)
from app.services.qualys_client import QualysApiClient
from app.services.misp_client import MispClient
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
        misp_url=settings.MISP_URL,
        misp_api_key_masked=_mask_token(settings.MISP_API_KEY),
        misp_creator_org=settings.MISP_CREATOR_ORG,
        misp_tag_filter=settings.MISP_TAG_FILTER,
        misp_feed_tag=settings.MISP_FEED_TAG,
        misp_enabled=settings.MISP_ENABLED,
        misp_mock_mode=settings.MISP_MOCK_MODE,
        misp_sync_interval_hours=settings.MISP_SYNC_INTERVAL_HOURS,
        misp_webhook_secret=_mask_token(settings.MISP_WEBHOOK_SECRET) if settings.MISP_WEBHOOK_SECRET else "",
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
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    if settings_in.qualys_api_url is not None:
        settings.QUALYS_API_URL = settings_in.qualys_api_url.strip().rstrip("/")
    if settings_in.qualys_username is not None:
        settings.QUALYS_USERNAME = settings_in.qualys_username.strip()
    if settings_in.qualys_password is not None and settings_in.qualys_password.strip():
        settings.QUALYS_PASSWORD = settings_in.qualys_password.strip()
    if settings_in.qualys_mock_mode is not None:
        settings.QUALYS_MOCK_MODE = settings_in.qualys_mock_mode
    if settings_in.qualys_sync_interval_hours is not None:
        settings.QUALYS_SYNC_INTERVAL_HOURS = settings_in.qualys_sync_interval_hours
    if settings_in.qualys_tag_filter is not None:
        settings.QUALYS_TAG_FILTER = settings_in.qualys_tag_filter.strip()

    if settings_in.misp_url is not None:
        settings.MISP_URL = settings_in.misp_url.strip().rstrip("/")
    if settings_in.misp_api_key is not None and settings_in.misp_api_key.strip():
        settings.MISP_API_KEY = settings_in.misp_api_key.strip()
    if settings_in.misp_creator_org is not None:
        settings.MISP_CREATOR_ORG = settings_in.misp_creator_org.strip()
    if settings_in.misp_tag_filter is not None:
        settings.MISP_TAG_FILTER = settings_in.misp_tag_filter.strip()
    if settings_in.misp_feed_tag is not None:
        settings.MISP_FEED_TAG = settings_in.misp_feed_tag.strip()
    if settings_in.misp_enabled is not None:
        settings.MISP_ENABLED = settings_in.misp_enabled
    if settings_in.misp_mock_mode is not None:
        settings.MISP_MOCK_MODE = settings_in.misp_mock_mode
    if settings_in.misp_sync_interval_hours is not None:
        settings.MISP_SYNC_INTERVAL_HOURS = settings_in.misp_sync_interval_hours
    if settings_in.misp_webhook_secret is not None:
        settings.MISP_WEBHOOK_SECRET = settings_in.misp_webhook_secret.strip()

    if settings_in.telegram_enabled is not None:
        settings.TELEGRAM_ENABLED = settings_in.telegram_enabled
    if settings_in.telegram_bot_token is not None and settings_in.telegram_bot_token.strip():
        settings.TELEGRAM_BOT_TOKEN = settings_in.telegram_bot_token.strip()
    if settings_in.telegram_chat_id is not None:
        settings.TELEGRAM_CHAT_ID = settings_in.telegram_chat_id.strip()
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

    # Persist all current settings to database
    items_to_persist = {
        "qualys_api_url": settings.QUALYS_API_URL,
        "qualys_username": settings.QUALYS_USERNAME,
        "qualys_password": settings.QUALYS_PASSWORD,
        "qualys_mock_mode": "true" if settings.QUALYS_MOCK_MODE else "false",
        "qualys_sync_interval_hours": str(settings.QUALYS_SYNC_INTERVAL_HOURS),
        "qualys_tag_filter": settings.QUALYS_TAG_FILTER,
        "misp_url": settings.MISP_URL,
        "misp_api_key": settings.MISP_API_KEY,
        "misp_creator_org": settings.MISP_CREATOR_ORG,
        "misp_tag_filter": settings.MISP_TAG_FILTER,
        "misp_feed_tag": settings.MISP_FEED_TAG,
        "misp_enabled": "true" if settings.MISP_ENABLED else "false",
        "misp_mock_mode": "true" if settings.MISP_MOCK_MODE else "false",
        "misp_sync_interval_hours": str(settings.MISP_SYNC_INTERVAL_HOURS),
        "misp_webhook_secret": settings.MISP_WEBHOOK_SECRET,
        "telegram_enabled": "true" if settings.TELEGRAM_ENABLED else "false",
        "telegram_bot_token": settings.TELEGRAM_BOT_TOKEN,
        "telegram_chat_id": settings.TELEGRAM_CHAT_ID,
        "telegram_cooldown_hours": str(settings.TELEGRAM_COOLDOWN_HOURS),
        "risk_threshold_critical": str(settings.RISK_THRESHOLD_CRITICAL),
        "risk_threshold_high": str(settings.RISK_THRESHOLD_HIGH),
        "sla_critical_days": str(settings.SLA_CRITICAL_DAYS),
        "sla_high_days": str(settings.SLA_HIGH_DAYS),
    }

    for k, v in items_to_persist.items():
        existing = await db.get(SystemSetting, k)
        if existing:
            existing.value = v
        else:
            db.add(SystemSetting(key=k, value=v, description="Persisted system setting"))
    await db.commit()

    return SystemSettingsResponse(
        qualys_api_url=settings.QUALYS_API_URL,
        qualys_username=settings.QUALYS_USERNAME,
        qualys_mock_mode=settings.QUALYS_MOCK_MODE,
        qualys_sync_interval_hours=settings.QUALYS_SYNC_INTERVAL_HOURS,
        qualys_tag_filter=settings.QUALYS_TAG_FILTER,
        misp_url=settings.MISP_URL,
        misp_api_key_masked=_mask_token(settings.MISP_API_KEY),
        misp_creator_org=settings.MISP_CREATOR_ORG,
        misp_tag_filter=settings.MISP_TAG_FILTER,
        misp_feed_tag=settings.MISP_FEED_TAG,
        misp_enabled=settings.MISP_ENABLED,
        misp_mock_mode=settings.MISP_MOCK_MODE,
        misp_sync_interval_hours=settings.MISP_SYNC_INTERVAL_HOURS,
        misp_webhook_secret=_mask_token(settings.MISP_WEBHOOK_SECRET) if settings.MISP_WEBHOOK_SECRET else "",
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


@router.post("/test-misp")
async def test_misp_connection(
    test_req: MispTestRequest,
    admin: User = Depends(require_admin),
):
    client = MispClient(
        base_url=test_req.misp_url,
        api_key=test_req.misp_api_key,
        creator_org=test_req.misp_creator_org,
        tag_filter=test_req.misp_tag_filter,
        feed_tag=test_req.misp_feed_tag,
        mock_mode=test_req.misp_mock_mode,
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

    msg = "🛡 <b>Risk Alert Dashboard: Test Alert</b>\n\n✅ Your Telegram Bot integration is configured correctly!"
    result = await TelegramService.send_message(msg, bot_token=token, chat_id=cid)
    return result
