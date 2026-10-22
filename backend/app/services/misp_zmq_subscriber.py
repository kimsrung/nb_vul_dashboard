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
from typing import Optional, List, Dict, Any

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.services.misp_client import MispClient
from app.services.proactive_assessment_engine import ProactiveAssessmentEngine
from app.services.telegram_service import TelegramService
from app.services.audit_service import AuditService

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("misp-zmq-subscriber")

_subscriber_task: Optional[asyncio.Task] = None
_stop_event = asyncio.Event()


async def process_misp_zmq_payload(topic: str, payload_str: str):
    """Parse MISP ZeroMQ JSON payload and trigger proactive asset assessment."""
    try:
        raw_data = json.loads(payload_str)
    except Exception as e:
        logger.warning(f"Failed to decode MISP ZMQ JSON on topic '{topic}': {e}")
        return

    # Extract event dictionary
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
        else:
            events_to_evaluate = [raw_data]

    client = MispClient()
    parsed_advisories = client._parse_misp_events(events_to_evaluate)
    if not parsed_advisories:
        logger.debug(f"ZMQ message received on '{topic}' but not matching FS-ISAC CVE criteria.")
        return

    logger.info(f"⚡ [MISP ZMQ Stream] Received {len(parsed_advisories)} FS-ISAC advisory candidate(s)")

    async with AsyncSessionLocal() as session:
        alerts_created = 0
        for adv in parsed_advisories:
            cve_id = adv.get("cve_id")
            logger.info(f"🔍 Evaluating FS-ISAC advisory {cve_id} against server inventory...")
            record = await ProactiveAssessmentEngine.assess_cve(session, adv)
            if record.affected_assets_count > 0:
                alerts_created += 1
                logger.warning(
                    f"🚨 [MISP ZMQ Alert Generated] {cve_id} matched {record.affected_assets_count} server(s) in inventory! "
                    f"Type: {record.match_type}"
                )
                if (
                    settings.TELEGRAM_ENABLED
                    and (record.severity or "").upper() in ("CRITICAL", "HIGH")
                    and not record.dispatched_telegram
                ):
                    try:
                        tg_text = TelegramService.format_misp_assessment_alert(record)
                        await TelegramService.send_message(tg_text)
                        record.dispatched_telegram = True
                    except Exception as te:
                        logger.error(f"Telegram dispatch failed: {te}")

        if alerts_created > 0:
            await AuditService.log_event(
                db=session,
                action="MISP_ZMQ_FEED_RECEIVED",
                target_type="MISP_Feed",
                target_id=str(parsed_advisories[0].get("cve_id", "ZMQ")),
                target_name=f"FS-ISAC ZMQ Stream ({len(parsed_advisories)} advisories, {alerts_created} matching alerts)",
                details={
                    "advisories_count": len(parsed_advisories),
                    "alerts_created": alerts_created,
                    "cves": [a.get("cve_id") for a in parsed_advisories[:10]],
                },
            )
        await session.commit()


async def zmq_subscriber_loop(host: str, port: int, topics: Optional[List[str]] = None):
    """Asynchronous ZeroMQ listener with automatic reconnect."""
    try:
        import zmq.asyncio
    except ImportError:
        logger.error("pyzmq package is required. Install via: pip install pyzmq")
        return

    if not topics:
        topics = ["misp_json_event", "misp_json"]

    target_addr = f"tcp://{host}:{port}"
    logger.info(f"Connecting to MISP ZeroMQ at {target_addr} on topics {topics}...")

    while not _stop_event.is_set():
        ctx = zmq.asyncio.Context()
        sock = ctx.socket(zmq.SUB)
        try:
            sock.connect(target_addr)
            for t in topics:
                sock.setsockopt_string(zmq.SUBSCRIBE, t)
            logger.info(f"Connected to MISP ZeroMQ at {target_addr}. Real-time feed subscription ACTIVE.")

            while not _stop_event.is_set():
                try:
                    # Non-blocking receive with timeout so loop can check _stop_event
                    if await sock.poll(timeout=1000):
                        msg = await sock.recv_string()
                        parts = msg.split(" ", 1)
                        if len(parts) >= 2:
                            topic, payload = parts[0], parts[1]
                            await process_misp_zmq_payload(topic, payload)
                except asyncio.CancelledError:
                    break
                except Exception as ex:
                    logger.error(f"Error reading from MISP ZMQ stream: {ex}")
                    break
        except Exception as conn_err:
            logger.error(f"Failed to connect to MISP ZeroMQ ({conn_err}). Retrying in 10s...")
            await asyncio.sleep(10)
        finally:
            try:
                sock.close()
                ctx.term()
            except Exception:
                pass


def start_misp_zmq_task(host: str, port: int, topics: Optional[List[str]] = None):
    """Start the ZeroMQ subscriber loop as an asyncio background task."""
    global _subscriber_task, _stop_event
    _stop_event.clear()
    loop = asyncio.get_event_loop()
    _subscriber_task = loop.create_task(zmq_subscriber_loop(host, port, topics))
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
    parser.add_argument("--topic", action="append", help="ZeroMQ Topic(s) (Defaults to misp_json_event and misp_json)")
    args = parser.parse_args()

    topics = args.topic or ["misp_json_event", "misp_json"]
    print(f"Starting MISP ZeroMQ Subscriber on tcp://{args.host}:{args.port}...")
    try:
        asyncio.run(zmq_subscriber_loop(args.host, args.port, topics))
    except KeyboardInterrupt:
        print("\nMISP ZeroMQ subscriber stopped by user.")
