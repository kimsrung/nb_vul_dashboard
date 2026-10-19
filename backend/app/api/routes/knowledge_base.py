from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.deps import require_viewer
from app.models.user import User
from app.models.knowledge_base import KnowledgeBase
from app.schemas.knowledge_base import KnowledgeBaseItem

router = APIRouter(prefix="/kb", tags=["KnowledgeBase"])


@router.get("/{qid}", response_model=KnowledgeBaseItem)
async def get_kb_detail(
    qid: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    kb = await db.get(KnowledgeBase, qid)
    if not kb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Qualys QID {qid} not found in local KnowledgeBase cache",
        )
    return kb
