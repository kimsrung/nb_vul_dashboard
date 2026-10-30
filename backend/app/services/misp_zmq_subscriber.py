"""
MISP ZeroMQ Real-Time Feed Subscriber Service
=============================================
Connects to MISP's native ZeroMQ publisher (tcp://<misp_host>:50000) and
streams published threat intelligence events in real-time.

When a new FS-ISAC CVE advisory is published or synchronized in MISP, this
service immediately evaluates it against the server software inventory
(AssetSoftware), registers threat alerts in the Alert Center, and dispatches
Telegram notifications.

Can run either:
1. Directly from CLI:
   python -m app.services.misp_zmq_subscriber --host 10.20.1.50 --port 50000
2. Automatically as a background task inside FastAPI app.
"""

import sys
import json
import logging
import argparse
import asyncio
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService
from app.services.audit_service import AuditService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("misp-zmq-subscriber")

_subscriber_task: Optional[asyncio.Task] = None
_stop_event = asyncio.Event()
_last_connected_at: Optional[datetime] = None
_last_message_at: Optional[datetime] = None
_messages_received_count: int = 0


def check_tcp_established(host: str, port: int) -> bool:
    """Check if an established TCP socket to host:port exists in Linux socket table (/proc/net/tcp)."""
    try:
        import os
        import socket
        if not os.path.exists("/proc/net/tcp"):
            return False
        # Resolve hostname to IPv4 address
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host
        ip_hex = "".join([f"{int(x):02X}" for x in reversed(ip.split("."))])
        port_hex = f"{port:04X}"
        match_str = f"{ip_hex}:{port_hex}".upper()
        with open("/proc/net/tcp") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2].upper() == match_str:
                    if parts[3] == "01":  # TCP_ESTABLISHED
                        return True
        return False
    except Exception:
        return False


def get_subscriber_status() -> Dict[str, Any]:
    """Retrieve runtime diagnostics of the ZeroMQ subscriber."""
    global _subscriber_task, _last_connected_at, _last_message_at, _messages_received_count
    host = (settings.MISP_ZMQ_HOST or "10.20.40.19").strip()
    port = settings.MISP_ZMQ_PORT or 50000
    is_established = check_tcp_established(host, port)
    is_running = (_subscriber_task is not None and not _subscriber_task.done()) or is_established

    return {
        "subscriber_active": is_running,
        "socket_established": is_established,
        "host": host,
        "port": port,
        "last_connected_at": _last_connected_at.isoformat() if _last_connected_at else None,
        "last_message_at": _last_message_at.isoformat() if _last_message_at else None,
        "messages_received_count": _messages_received_count,
    }


async def process_misp_push_payload(
    raw_data: Any,
    source_channel: str = "ZeroMQ Stream",
    topic: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse MISP threat event payload from ZeroMQ stream and trigger proactive asset assessment.

    1. Extracts MISP Event structures from payload.
    2. Identifies FS-ISAC CVE candidate advisories.
    3. Evaluates candidates against active inventory (Qualys QIDs, software packages, OS platforms).
    4. Persists assessment records (instantly reflected on /alerts and Dashboard KPIs).
    5. Dispatches formatted Telegram alert for Critical/High severity matches affecting inventory.
    6. Records comprehensive audit trail in audit_logs.
    """
    events_to_evaluate = []
    if isinstance(raw_data, list):
        events_to_evaluate = raw_data
    elif isinstance(raw_data, dict):
        if "Event" in raw_data:
            events_to_evaluate = [raw_data]
        elif "event" in raw_data:
            events_to_evaluate = [raw_data["event"]]
        elif "data" in raw_data and isinstance(raw_data["data"], dict) and "Event" in raw_data["data"]:
            events_to_evaluate = [raw_data["data"]]
        elif "Attribute" in raw_data:
            attr = raw_data["Attribute"]
            events_to_evaluate = [{
                "Event": {
                    "id": str(attr.get("event_id", "")),
                    "info": f"MISP Live Attribute {attr.get('type')}: {attr.get('value')}",
                    "Attribute": [attr],
                    "Tag": attr.get("Tag", []),
                }
            }]
        else:
            events_to_evaluate = [raw_data]

    client = MispClient()
    parsed_advisories = client._parse_misp_events(events_to_evaluate)
    if not parsed_advisories:
        logger.debug(f"{source_channel} message received but contained no events matching FS-ISAC CVE criteria.")
        return {
            "success": True,
            "message": f"Payload received via {source_channel} but contained no events matching FS-ISAC CVE criteria.",
            "advisories_evaluated": 0,
            "matching_alerts_created": 0,
            "evaluated_cves": [],
            "details": [],
        }

    logger.info(f"⚡ [MISP {source_channel}] Received {len(parsed_advisories)} FS-ISAC advisory candidate(s)")

    evaluated_details: List[Dict[str, Any]] = []
    async with AsyncSessionLocal() as session:
        alerts_created = 0
        for adv in parsed_advisories:
            cve_id = adv.get("cve_id")
            logger.info(f"🔍 Evaluating FS-ISAC advisory {cve_id} against server inventory...")
            record = await ProactiveAssessmentEngine.assess_cve(session, adv)
            affected_count = record.affected_assets_count
            matched_flag = affected_count > 0

            if matched_flag:
                alerts_created += 1
                logger.warning(
                    f"🚨 [MISP {source_channel} Alert Generated] {cve_id} matched {affected_count} server(s) in inventory! "
                    f"Type: {record.match_type}"
                )
                if (
                    settings.TELEGRAM_ENABLED
                    and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                    and not record.dispatched_telegram
                ):
                    try:
                        tg_text = TelegramService.format_misp_assessment_alert(record)
                        tg_res = await TelegramService.send_message(tg_text)
                        if tg_res.get("success"):
                            record.dispatched_telegram = True
                            record.telegram_sent_at = datetime.now(timezone.utc)
                    except Exception as te:
                        logger.error(f"Telegram dispatch failed: {te}")

            evaluated_details.append({
                "cve_id": cve_id,
                "title": record.title,
                "severity": record.severity,
                "cvss_score": record.cvss_score,
                "match_type": record.match_type,
                "affected_assets_count": affected_count,
                "dispatched_telegram": record.dispatched_telegram,
            })

            # Record audit log for EVERY event triggered from MISP (whether matched or clean)
            status_desc = f"{affected_count} server(s) affected" if matched_flag else "0 servers affected (Clean)"
            await AuditService.log_event(
                db=session,
                action="MISP_EVENT_TRIGGERED",
                target_type="MISP_Advisory",
                target_id=str(cve_id),
                target_name=f"{cve_id} ({adv.get('affected_product', 'software')}) — {status_desc}",
                details={
                    "cve_id": cve_id,
                    "title": adv.get("title") or record.title,
                    "affected_product": adv.get("affected_product"),
                    "vulnerable_versions": adv.get("vulnerable_versions"),
                    "severity": record.severity,
                    "cvss_score": record.cvss_score,
                    "affected_assets_count": affected_count,
                    "match_type": record.match_type,
                    "matched_in_inventory": matched_flag,
                    "source": source_channel,
                    "misp_event_id": adv.get("misp_event_id"),
                },
            )

        # Update last sync time watermark in system_settings
        now_str = datetime.now(timezone.utc).isoformat()
        sync_setting = await session.get(SystemSetting, "misp_last_sync_time")
        if sync_setting:
            sync_setting.value = now_str
        else:
            session.add(SystemSetting(key="misp_last_sync_time", value=now_str, description="Timestamp of last MISP sync/push"))

        # Bulk stream log summary
        audit_action = "MISP_ZMQ_FEED_RECEIVED"
        await AuditService.log_event(
            db=session,
            action=audit_action,
            target_type="MISP_Feed",
            target_id=str(parsed_advisories[0].get("cve_id", "LIVE_PUSH")),
            target_name=f"FS-ISAC {source_channel} ({len(parsed_advisories)} advisories, {alerts_created} matching alerts)",
            details={
                "source_channel": source_channel,
                "topic": topic,
                "advisories_count": len(parsed_advisories),
                "alerts_created": alerts_created,
                "cves": [a.get("cve_id") for a in parsed_advisories[:10]],
            },
        )
        await session.commit()

    return {
        "success": True,
        "message": f"Successfully evaluated {len(parsed_advisories)} FS-ISAC advisory candidate(s) via {source_channel}: {alerts_created} matching alert(s) generated.",
        "advisories_evaluated": len(parsed_advisories),
        "matching_alerts_created": alerts_created,
        "evaluated_cves": [a.get("cve_id") for a in parsed_advisories if a.get("cve_id")],
        "details": evaluated_details,
    }


async def process_misp_zmq_payload(topic: str, payload_str: str):
    """Parse MISP ZeroMQ JSON payload and trigger proactive asset assessment."""
    try:
        raw_data = json.loads(payload_str)
    except Exception as e:
        logger.warning(f"Failed to decode MISP ZMQ JSON on topic '{topic}': {e}")
        return

    await process_misp_push_payload(raw_data, source_channel="ZeroMQ Stream", topic=topic)


async def zmq_subscriber_loop(
    host: str,
    port: int,
    topics: Optional[List[str]] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
):
    """Asynchronous ZeroMQ listener with automatic reconnect, PLAIN auth, and robust multi-frame support."""
    try:
        import zmq.asyncio
    except ImportError:
        logger.error("pyzmq package is required. Install via: pip install pyzmq")
        return

    if not topics:
        topics = ["misp_json_event", "misp_json", "misp_json_attribute"]

    user = username if username is not None else settings.MISP_ZMQ_USERNAME
    pwd = password if password is not None else settings.MISP_ZMQ_PASSWORD

    target_addr = f"tcp://{host}:{port}"
    auth_desc = f"with user '{user}'" if user else "unauthenticated"
    logger.info(f"Connecting to MISP ZeroMQ at {target_addr} ({auth_desc}) on topics {topics}...")

    retry_delay = 5
    while not _stop_event.is_set():
        ctx = zmq.asyncio.Context()
        sock = ctx.socket(zmq.SUB)
        # Set receive timeout and linger
        sock.setsockopt(zmq.LINGER, 0)
        sock.setsockopt(zmq.RCVTIMEO, 2000)
        sock.setsockopt(zmq.TCP_KEEPALIVE, 1)        # Enable TCP keepalive probes
        sock.setsockopt(zmq.TCP_KEEPALIVE_IDLE, 30)   # Send probe after 30s of silence
        sock.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 10)  # Retry probe every 10s
        sock.setsockopt(zmq.TCP_KEEPALIVE_CNT, 3)     # Drop after 3 dropped probes
        sock.setsockopt(zmq.RECONNECT_IVL, 1000)      # Reconnect after 1s on drop
        sock.setsockopt(zmq.RECONNECT_IVL_MAX, 5000)  # Max reconnect backoff 5s

        # Configure ZeroMQ PLAIN authentication if credentials are provided
        if user and pwd:
            sock.setsockopt_string(zmq.PLAIN_USERNAME, user)
            sock.setsockopt_string(zmq.PLAIN_PASSWORD, pwd)

        try:
            global _last_connected_at, _last_message_at, _messages_received_count
            sock.connect(target_addr)
            for t in topics:
                sock.setsockopt_string(zmq.SUBSCRIBE, t)
            _last_connected_at = datetime.now(timezone.utc)
            logger.info(f"Connected to MISP ZeroMQ at {target_addr}. Real-time feed subscription ACTIVE.")
            retry_delay = 5  # Reset delay on successful connection

            while not _stop_event.is_set():
                try:
                    if await sock.poll(timeout=1000):
                        frames = await sock.recv_multipart()
                        if not frames:
                            continue
                        _last_message_at = datetime.now(timezone.utc)
                        _messages_received_count += 1
                        if len(frames) == 1:
                            raw_str = frames[0].decode("utf-8", errors="replace")
                            parts = raw_str.split(" ", 1)
                            if len(parts) >= 2:
                                topic, payload = parts[0], parts[1]
                            else:
                                topic, payload = "misp_json_event", raw_str
                        else:
                            topic = frames[0].decode("utf-8", errors="replace").strip()
                            payload = frames[1].decode("utf-8", errors="replace")

                        await process_misp_zmq_payload(topic, payload)
                except zmq.Again:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as ex:
                    logger.error(f"Error reading from MISP ZMQ stream: {ex}")
                    break
        except Exception as conn_err:
            logger.warning(f"MISP ZeroMQ connection at {target_addr} unavailable ({conn_err}). Retrying in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)
        finally:
            try:
                sock.close()
                ctx.term()
            except Exception:
                pass


def start_misp_zmq_task(
    host: str,
    port: int,
    topics: Optional[List[str]] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
):
    """Start the ZeroMQ subscriber loop as an asyncio background task."""
    global _subscriber_task, _stop_event
    _stop_event.clear()
    loop = asyncio.get_event_loop()
    _subscriber_task = loop.create_task(
        zmq_subscriber_loop(host, port, topics, username, password)
    )
    return _subscriber_task


def stop_misp_zmq_task():
    """Stop the ZeroMQ subscriber task."""
    global _subscriber_task, _stop_event
    _stop_event.set()
    if _subscriber_task and not _subscriber_task.done():
        _subscriber_task.cancel()
        logger.info("MISP ZeroMQ subscriber task cancelled.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MISP ZeroMQ Live Feed Subscriber")
    parser.add_argument("--host", default="127.0.0.1", help="MISP ZeroMQ Server Host (Default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=50000, help="MISP ZeroMQ Port (Default: 50000)")
    parser.add_argument("--username", default=None, help="MISP ZeroMQ PLAIN Username")
    parser.add_argument("--password", default=None, help="MISP ZeroMQ PLAIN Password")
    parser.add_argument("--topic", action="append", help="ZeroMQ Topic(s) (Defaults to misp_json_event and misp_json)")
    args = parser.parse_args()

    topics = args.topic or ["misp_json_event", "misp_json", "misp_json_attribute"]
    auth_str = f"with user '{args.username}'" if args.username else "unauthenticated"
    print(f"Starting MISP ZeroMQ Subscriber on tcp://{args.host}:{args.port} ({auth_str})...")
    try:
        asyncio.run(zmq_subscriber_loop(args.host, args.port, topics, args.username, args.password))
    except KeyboardInterrupt:
        print("\nMISP ZeroMQ subscriber stopped by user.")
