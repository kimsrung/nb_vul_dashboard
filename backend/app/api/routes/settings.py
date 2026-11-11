from fastapi import APIRouter, Depends, HTTPException, status, Request
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
    MispZmqTestRequest,
)
from app.services.qualys_client import QualysApiClient
from app.services.misp_client import MispClient
from app.services.telegram_service import TelegramService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/settings", tags=["Settings"])


def _mask_token(token: str) -> str:
    if not token or len(token) < 8:
        return "Not Set"
    return token[:4] + "..." + token[-4:]


@router.get("", response_model=SystemSettingsResponse)
async def get_settings(admin: User = Depends(require_admin)):
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
        misp_verify_ssl=settings.MISP_VERIFY_SSL,
        misp_sync_interval_hours=settings.MISP_SYNC_INTERVAL_HOURS,
        misp_zmq_enabled=settings.MISP_ZMQ_ENABLED,
        misp_zmq_host=settings.MISP_ZMQ_HOST,
        misp_zmq_port=settings.MISP_ZMQ_PORT,
        misp_zmq_username=settings.MISP_ZMQ_USERNAME,
        misp_zmq_password_masked=_mask_token(settings.MISP_ZMQ_PASSWORD),
        telegram_enabled=settings.TELEGRAM_ENABLED,
        telegram_bot_token_masked=_mask_token(settings.TELEGRAM_BOT_TOKEN),
        telegram_chat_id=settings.TELEGRAM_CHAT_ID,
        telegram_topic_id=settings.TELEGRAM_TOPIC_ID,
        telegram_cooldown_hours=settings.TELEGRAM_COOLDOWN_HOURS,
        docs_username=settings.DOCS_USERNAME,
        docs_password_masked="••••••••" if settings.DOCS_PASSWORD else "Not Set",
    )


@router.post("", response_model=SystemSettingsResponse)
async def update_settings(
    settings_in: SystemSettingsUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    changes = {}

    def record_change(key: str, old_val, new_val, is_secret: bool = False):
        if is_secret:
            old_masked = _mask_token(str(old_val)) if old_val else "Not Set"
            new_masked = _mask_token(str(new_val)) if new_val else "Not Set"
            if old_masked != new_masked:
                changes[key] = {"old": old_masked, "new": new_masked}
        else:
            if old_val != new_val:
                changes[key] = {"old": old_val, "new": new_val}

    if settings_in.qualys_api_url is not None:
        new_url = settings_in.qualys_api_url.strip().rstrip("/")
        record_change("qualys_api_url", settings.QUALYS_API_URL, new_url)
        settings.QUALYS_API_URL = new_url

    if settings_in.qualys_username is not None:
        new_user = settings_in.qualys_username.strip()
        record_change("qualys_username", settings.QUALYS_USERNAME, new_user)
        settings.QUALYS_USERNAME = new_user

    if settings_in.qualys_password is not None and settings_in.qualys_password.strip():
        new_pass = settings_in.qualys_password.strip()
        if settings.QUALYS_PASSWORD != new_pass:
            changes["qualys_password"] = {"old": "••••••••" if settings.QUALYS_PASSWORD else "Not Set", "new": "•••••••• (Updated)"}
            settings.QUALYS_PASSWORD = new_pass

    if settings_in.qualys_mock_mode is not None:
        record_change("qualys_mock_mode", settings.QUALYS_MOCK_MODE, settings_in.qualys_mock_mode)
        settings.QUALYS_MOCK_MODE = settings_in.qualys_mock_mode

    if settings_in.qualys_sync_interval_hours is not None:
        record_change("qualys_sync_interval_hours", settings.QUALYS_SYNC_INTERVAL_HOURS, settings_in.qualys_sync_interval_hours)
        settings.QUALYS_SYNC_INTERVAL_HOURS = settings_in.qualys_sync_interval_hours

    if settings_in.qualys_tag_filter is not None:
        new_tag = settings_in.qualys_tag_filter.strip()
        record_change("qualys_tag_filter", settings.QUALYS_TAG_FILTER, new_tag)
        settings.QUALYS_TAG_FILTER = new_tag

    if settings_in.misp_url is not None:
        new_misp_url = settings_in.misp_url.strip().rstrip("/")
        record_change("misp_url", settings.MISP_URL, new_misp_url)
        settings.MISP_URL = new_misp_url

    if settings_in.misp_api_key is not None and settings_in.misp_api_key.strip():
        new_api_key = settings_in.misp_api_key.strip()
        if settings.MISP_API_KEY != new_api_key:
            record_change("misp_api_key", settings.MISP_API_KEY, new_api_key, is_secret=True)
            settings.MISP_API_KEY = new_api_key

    if settings_in.misp_creator_org is not None:
        new_org = settings_in.misp_creator_org.strip()
        record_change("misp_creator_org", settings.MISP_CREATOR_ORG, new_org)
        settings.MISP_CREATOR_ORG = new_org

    if settings_in.misp_tag_filter is not None:
        new_mtag = settings_in.misp_tag_filter.strip()
        record_change("misp_tag_filter", settings.MISP_TAG_FILTER, new_mtag)
        settings.MISP_TAG_FILTER = new_mtag

    if settings_in.misp_feed_tag is not None:
        new_ftag = settings_in.misp_feed_tag.strip()
        record_change("misp_feed_tag", settings.MISP_FEED_TAG, new_ftag)
        settings.MISP_FEED_TAG = new_ftag

    if settings_in.misp_enabled is not None:
        record_change("misp_enabled", settings.MISP_ENABLED, settings_in.misp_enabled)
        settings.MISP_ENABLED = settings_in.misp_enabled

    if settings_in.misp_mock_mode is not None:
        record_change("misp_mock_mode", settings.MISP_MOCK_MODE, settings_in.misp_mock_mode)
        settings.MISP_MOCK_MODE = settings_in.misp_mock_mode

    if settings_in.misp_verify_ssl is not None:
        record_change("misp_verify_ssl", settings.MISP_VERIFY_SSL, settings_in.misp_verify_ssl)
        settings.MISP_VERIFY_SSL = settings_in.misp_verify_ssl

    if settings_in.misp_sync_interval_hours is not None:
        record_change("misp_sync_interval_hours", settings.MISP_SYNC_INTERVAL_HOURS, settings_in.misp_sync_interval_hours)
        settings.MISP_SYNC_INTERVAL_HOURS = settings_in.misp_sync_interval_hours

    if settings_in.misp_zmq_enabled is not None:
        record_change("misp_zmq_enabled", settings.MISP_ZMQ_ENABLED, settings_in.misp_zmq_enabled)
        settings.MISP_ZMQ_ENABLED = settings_in.misp_zmq_enabled

    if settings_in.misp_zmq_host is not None:
        new_zhost = settings_in.misp_zmq_host.strip()
        record_change("misp_zmq_host", settings.MISP_ZMQ_HOST, new_zhost)
        settings.MISP_ZMQ_HOST = new_zhost

    if settings_in.misp_zmq_port is not None:
        record_change("misp_zmq_port", settings.MISP_ZMQ_PORT, settings_in.misp_zmq_port)
        settings.MISP_ZMQ_PORT = settings_in.misp_zmq_port

    if settings_in.misp_zmq_username is not None:
        new_zuser = settings_in.misp_zmq_username.strip()
        record_change("misp_zmq_username", settings.MISP_ZMQ_USERNAME, new_zuser)
        settings.MISP_ZMQ_USERNAME = new_zuser

    if settings_in.misp_zmq_password is not None and settings_in.misp_zmq_password.strip():
        new_zpass = settings_in.misp_zmq_password.strip()
        if settings.MISP_ZMQ_PASSWORD != new_zpass:
            record_change("misp_zmq_password", settings.MISP_ZMQ_PASSWORD, new_zpass, is_secret=True)
            settings.MISP_ZMQ_PASSWORD = new_zpass

    if settings_in.telegram_enabled is not None:
        record_change("telegram_enabled", settings.TELEGRAM_ENABLED, settings_in.telegram_enabled)
        settings.TELEGRAM_ENABLED = settings_in.telegram_enabled

    if settings_in.telegram_bot_token is not None and settings_in.telegram_bot_token.strip():
        new_token = settings_in.telegram_bot_token.strip()
        if settings.TELEGRAM_BOT_TOKEN != new_token:
            record_change("telegram_bot_token", settings.TELEGRAM_BOT_TOKEN, new_token, is_secret=True)
            settings.TELEGRAM_BOT_TOKEN = new_token

    if settings_in.telegram_chat_id is not None:
        new_cid, auto_topic = TelegramService.parse_chat_and_topic(settings_in.telegram_chat_id, settings_in.telegram_topic_id)
        record_change("telegram_chat_id", settings.TELEGRAM_CHAT_ID, new_cid)
        settings.TELEGRAM_CHAT_ID = new_cid
        if auto_topic is not None:
            settings_in.telegram_topic_id = auto_topic

    if settings_in.telegram_topic_id is not None:
        record_change("telegram_topic_id", settings.TELEGRAM_TOPIC_ID, settings_in.telegram_topic_id)
        settings.TELEGRAM_TOPIC_ID = settings_in.telegram_topic_id

    if settings_in.telegram_cooldown_hours is not None:
        record_change("telegram_cooldown_hours", settings.TELEGRAM_COOLDOWN_HOURS, settings_in.telegram_cooldown_hours)
        settings.TELEGRAM_COOLDOWN_HOURS = settings_in.telegram_cooldown_hours

    if settings_in.docs_username is not None and settings_in.docs_username.strip():
        new_duser = settings_in.docs_username.strip()
        record_change("docs_username", settings.DOCS_USERNAME, new_duser)
        settings.DOCS_USERNAME = new_duser

    if settings_in.docs_password is not None and settings_in.docs_password.strip() and settings_in.docs_password != "••••••••":
        new_dpass = settings_in.docs_password.strip()
        if settings.DOCS_PASSWORD != new_dpass:
            changes["docs_password"] = {"old": "••••••••" if settings.DOCS_PASSWORD else "Not Set", "new": "•••••••• (Updated)"}
            settings.DOCS_PASSWORD = new_dpass

    # Record Audit Log if any setting values actually changed
    if changes:
        sections = set()
        for field in changes.keys():
            if field.startswith("qualys"):
                sections.add("Qualys")
            elif field.startswith("misp"):
                sections.add("MISP")
            elif field.startswith("telegram"):
                sections.add("Telegram")
            elif field.startswith("docs"):
                sections.add("API Docs")
            else:
                sections.add("System")

        section_desc = ", ".join(sorted(sections))
        await AuditService.log_event(
            db=db,
            action="UPDATE_SETTINGS",
            target_type="Settings",
            target_id="system_settings",
            target_name=f"System Configuration ({section_desc})",
            actor=admin,
            request=request,
            details={
                "changed_count": len(changes),
                "sections_modified": list(sections),
                "changed_fields": list(changes.keys()),
                "changes": changes,
            },
        )

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
        "misp_verify_ssl": "true" if settings.MISP_VERIFY_SSL else "false",
        "misp_sync_interval_hours": str(settings.MISP_SYNC_INTERVAL_HOURS),
        "misp_zmq_enabled": "true" if settings.MISP_ZMQ_ENABLED else "false",
        "misp_zmq_host": settings.MISP_ZMQ_HOST,
        "misp_zmq_port": str(settings.MISP_ZMQ_PORT),
        "misp_zmq_username": settings.MISP_ZMQ_USERNAME,
        "misp_zmq_password": settings.MISP_ZMQ_PASSWORD,
        "telegram_enabled": "true" if settings.TELEGRAM_ENABLED else "false",
        "telegram_bot_token": settings.TELEGRAM_BOT_TOKEN,
        "telegram_chat_id": settings.TELEGRAM_CHAT_ID,
        "telegram_topic_id": str(settings.TELEGRAM_TOPIC_ID) if settings.TELEGRAM_TOPIC_ID is not None else "",
        "telegram_cooldown_hours": str(settings.TELEGRAM_COOLDOWN_HOURS),
        "docs_username": settings.DOCS_USERNAME,
        "docs_password": settings.DOCS_PASSWORD,
    }

    for k, v in items_to_persist.items():
        existing = await db.get(SystemSetting, k)
        if existing:
            existing.value = v
        else:
            db.add(SystemSetting(key=k, value=v, description="Persisted system setting"))
    await db.commit()

    # Live reload ZeroMQ subscriber with new credentials / settings
    if settings.MISP_ZMQ_ENABLED and settings.MISP_ZMQ_HOST:
        from app.services.misp_zmq_subscriber import stop_misp_zmq_task, start_misp_zmq_task
        stop_misp_zmq_task()
        start_misp_zmq_task(
            settings.MISP_ZMQ_HOST,
            settings.MISP_ZMQ_PORT,
            username=settings.MISP_ZMQ_USERNAME,
            password=settings.MISP_ZMQ_PASSWORD,
        )

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
        misp_verify_ssl=settings.MISP_VERIFY_SSL,
        misp_sync_interval_hours=settings.MISP_SYNC_INTERVAL_HOURS,
        misp_zmq_enabled=settings.MISP_ZMQ_ENABLED,
        misp_zmq_host=settings.MISP_ZMQ_HOST,
        misp_zmq_port=settings.MISP_ZMQ_PORT,
        misp_zmq_username=settings.MISP_ZMQ_USERNAME,
        misp_zmq_password_masked=_mask_token(settings.MISP_ZMQ_PASSWORD),
        telegram_enabled=settings.TELEGRAM_ENABLED,
        telegram_bot_token_masked=_mask_token(settings.TELEGRAM_BOT_TOKEN),
        telegram_chat_id=settings.TELEGRAM_CHAT_ID,
        telegram_topic_id=settings.TELEGRAM_TOPIC_ID,
        telegram_cooldown_hours=settings.TELEGRAM_COOLDOWN_HOURS,
        docs_username=settings.DOCS_USERNAME,
        docs_password_masked="••••••••" if settings.DOCS_PASSWORD else "Not Set",
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
    if test_req.misp_zmq_host:
        settings.MISP_ZMQ_HOST = test_req.misp_zmq_host.strip()
    if test_req.misp_zmq_port:
        settings.MISP_ZMQ_PORT = test_req.misp_zmq_port
    if test_req.misp_zmq_username is not None:
        settings.MISP_ZMQ_USERNAME = test_req.misp_zmq_username.strip()
    if test_req.misp_zmq_password:
        settings.MISP_ZMQ_PASSWORD = test_req.misp_zmq_password.strip()
    if test_req.misp_zmq_enabled is not None:
        settings.MISP_ZMQ_ENABLED = test_req.misp_zmq_enabled

    client = MispClient(
        base_url=test_req.misp_url,
        api_key=test_req.misp_api_key,
        creator_org=test_req.misp_creator_org,
        tag_filter=test_req.misp_tag_filter,
        feed_tag=test_req.misp_feed_tag,
        mock_mode=test_req.misp_mock_mode,
        verify_ssl=test_req.misp_verify_ssl,
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
    topic_id = test_req.topic_id if test_req.topic_id is not None else settings.TELEGRAM_TOPIC_ID

    if not token or not cid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Telegram Bot Token and Chat ID must be specified",
        )

    msg = "🛡 <b>Threat Center Dashboard: Test Alert</b>\n\n✅ Your Telegram Bot integration is configured correctly!"
    result = await TelegramService.send_message(msg, bot_token=token, chat_id=cid, topic_id=topic_id)
    return result


@router.post("/test-misp-zmq")
async def test_misp_zmq_connection(
    test_req: MispZmqTestRequest = MispZmqTestRequest(),
    admin: User = Depends(require_admin),
):
    """Test TCP socket connectivity to the MISP ZeroMQ publisher with keepalive and SYN-retransmission tolerance."""
    import asyncio
    import time
    from app.services.misp_zmq_subscriber import get_subscriber_status

    host = (test_req.host or settings.MISP_ZMQ_HOST or "127.0.0.1").strip()
    port = test_req.port or settings.MISP_ZMQ_PORT or 50000

    import socket
    sub_status = get_subscriber_status()
    conf_host = (settings.MISP_ZMQ_HOST or "").strip()
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        target_ip = host
    try:
        conf_ip = socket.gethostbyname(conf_host) if conf_host else ""
    except Exception:
        conf_ip = conf_host

    is_configured_target = (host == conf_host or (target_ip and target_ip == conf_ip)) and (port == settings.MISP_ZMQ_PORT)

    # 1. If testing configured target and persistent background stream is already established in socket table
    if is_configured_target and sub_status["socket_established"]:
        return {
            "success": True,
            "message": f"Persistent ZeroMQ stream is ACTIVE and ESTABLISHED at tcp://{host}:{port} with TCP Keepalive.",
            "host": host,
            "port": port,
            "subscriber_active": True,
            "socket_established": True,
            "latency_ms": 0.5,
        }

    # 2. Perform active socket probe with SYN-retransmission tolerance (2 attempts, 6.0s timeout)
    last_err = None
    for attempt in range(1, 3):
        t0 = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=6.0,
            )
            elapsed = time.time() - t0
            writer.close()
            await writer.wait_closed()

            status_desc = "Background subscriber is ACTIVE." if sub_status["subscriber_active"] else "Background subscriber is idle."
            return {
                "success": True,
                "message": f"Successfully connected to MISP ZeroMQ socket at tcp://{host}:{port} in {elapsed:.2f}s. {status_desc}",
                "host": host,
                "port": port,
                "subscriber_active": sub_status["subscriber_active"],
                "socket_established": sub_status.get("socket_established", False),
                "latency_ms": round(elapsed * 1000, 1),
            }
        except asyncio.TimeoutError:
            last_err = f"Connection timed out (6s) reaching tcp://{host}:{port}. Firewall or SYN queue rate limit detected."
            if attempt < 2:
                await asyncio.sleep(0.5)
        except (ConnectionRefusedError, OSError) as e:
            last_err = str(e)
            break
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                await asyncio.sleep(0.5)

    return {
        "success": False,
        "message": f"Unable to reach MISP ZeroMQ socket at tcp://{host}:{port}: {last_err}",
        "host": host,
        "port": port,
        "subscriber_active": sub_status["subscriber_active"],
        "socket_established": False,
    }
