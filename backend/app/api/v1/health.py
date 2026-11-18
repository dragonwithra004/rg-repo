"""Health and database connectivity check endpoint."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.schemas.auth import HealthResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    now = datetime.now(timezone.utc)
    try:
        await db.execute(text("SELECT 1"))
        return HealthResponse(
            status="online",
            database="connected",
            environment=settings.environment,
            timestamp=now,
        )
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=HealthResponse(
                status="degraded",
                database="unreachable",
                environment=settings.environment,
                timestamp=now,
            ).model_dump(mode="json"),
        )
