from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Request
from app.models.audit_log import AuditLog
from app.models.user import User


class AuditService:
    @staticmethod
    async def log_event(
        db: AsyncSession,
        action: str,
        target_type: str,
        target_id: str | int,
        target_name: Optional[str] = None,
        actor: Optional[User] = None,
        request: Optional[Request] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        client_ip = ip_address
        if not client_ip and request and request.client:
            client_ip = request.client.host

        audit_entry = AuditLog(
            action=action,
            target_type=target_type,
            target_id=str(target_id),
            target_name=target_name,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "System",
            actor_role=actor.role if actor else "system",
            ip_address=client_ip,
            details=details or {},
            created_at=datetime.now(timezone.utc),
        )
        db.add(audit_entry)
        return audit_entry
