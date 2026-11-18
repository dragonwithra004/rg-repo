# RG STUDIO MANAGEMENT SYSTEM — Phase 1 Architecture & Windows 10 Verification Guide

## 1. Phase 1 Scope
- Modular repository layout (`backend/`, `desktop/`, `migrations/`, `docs/`, plus interactive Phase 1 sandbox preview in `server.ts` & `src/`)
- Supabase PostgreSQL 20-table normalized relational schema (`migrations/001_initial_schema.sql` & Alembic `0001_initial_schema`)
- FastAPI REST foundation with SQLAlchemy 2.0 `asyncpg` TLS pooling and `psycopg` sync Alembic migrations
- Argon2id password hashing + JWT Access/Refresh tokens + login lockout protection
- Three strict RBAC roles (`admin`, `manager`, `employee`) enforced on backend routes
- Secure first-run Administrator bootstrap (`POST /api/v1/setup/admin`) with zero hardcoded default passwords
- PySide6 Windows desktop shell with Light/Dark QSS themes, `Online`/`Offline`/`Synchronizing` state monitor, and read-only offline cache

## 2. Database Drivers & Supabase SSL Configuration
- `RG_DATABASE_URL`: MUST use `postgresql+asyncpg://...` (runtime FastAPI async engine). `backend/app/db/session.py` strips unsupported `sslmode=` query parameters and attaches a TLS `ssl.create_default_context()` plus `statement_cache_size=0` for Supabase Supavisor port `6543`.
- `RG_DATABASE_SYNC_URL`: MUST use `postgresql+psycopg://...?sslmode=require` (Alembic migrations).
- `RG_API_BASE_URL`: Intentionally left blank in `.env.example` until the FastAPI backend is deployed over HTTPS. Never assume `localhost:3000` is the FastAPI backend.

## 3. Windows 10 Local Dependency Installation & Pytest Verification
Run the following commands in **PowerShell** on Windows 10 (Python 3.11+ installed):

### Backend Environment & Pytest
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:PYTHONPATH="."
pytest -v
```

### Desktop Shell Environment
```powershell
cd desktop
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

### Alembic Migration Check (Only after setting real Supabase credentials in server-side `.env`)
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
alembic upgrade head
```
