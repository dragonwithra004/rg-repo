"""Admin-only infrastructure status and live DB probe endpoints (zero secret exposure)."""

from fastapi import APIRouter, Depends

from app.api.deps import CurrentActor, require_roles
from app.core.startup_restore import (
    get_startup_state,
    run_fastapi_startup_restore,
    verify_required_tables,
)

router = APIRouter(prefix="/admin/infra", tags=["Infrastructure"])


@router.get("/status")
async def get_admin_infra_status(
    _actor: CurrentActor = Depends(require_roles("admin")),
):
    return get_startup_state()


@router.post("/test-db")
async def test_admin_db_connection(
    _actor: CurrentActor = Depends(require_roles("admin")),
):
    state = await run_fastapi_startup_restore()
    return {
        "overall_status": state.overall_status,
        "supabase_configured": state.supabase_configured,
        "database_connected": state.database_connected,
        "jwt_configured": state.jwt_configured,
        "encryption_key_configured": state.encryption_key_configured,
        "persistent_storage_mode": state.persistent_storage_mode,
        "masked_db_host": state.masked_db_host,
        "restored_at": state.restored_at,
        "last_error": state.last_error,
        "tls_diagnostics": state.tls_diagnostics,
    }


@router.post("/verify-tables")
async def verify_admin_required_tables(
    _actor: CurrentActor = Depends(require_roles("admin")),
):
    return await verify_required_tables()
