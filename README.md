# QuantumShield v2.0 — Production-Ready PQC Scanner

**Post-Quantum Cryptography Scanner with Auth, Database & Scan History**

---

## What's New in v2.0

- ✅ JWT authentication with SQLite database
- ✅ Role-based access control (Admin / Operator / Checker / Viewer)
- ✅ Full scan history persisted to database
- ✅ Audit logs for every login, scan, and action
- ✅ Admin panel for user management
- ✅ Password change functionality
- ✅ Auto-seeds 3 default users on first run

---

## Quick Start (Local)

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5173  
Backend API docs: http://localhost:8000/docs

---

## Docker

```bash
docker compose up -d
```

Frontend: http://localhost:3000  
Backend: http://localhost:8000

---

## Default Login Credentials

| Username | Password     | Role     |
|----------|-------------|----------|
| admin    | quantum2026 | Admin    |
| pnb      | pnbsecure   | Operator |
| auditor  | audit2026   | Checker  |

---

## Deploy to Render + Vercel (Free)

### Backend (Render)
1. New Web Service → connect GitHub repo
2. Root Directory: `backend`
3. Build Command: `pip install -r requirements.txt`
4. Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables:
   - `SECRET_KEY` = (random long string)
   - `ADMIN_REGISTER_KEY` = (secret for creating users)

### Frontend (Vercel)
1. New Project → connect GitHub repo
2. Root Directory: `frontend`
3. Framework: Vite
4. Add environment variable:
   - `VITE_BACKEND_URL` = https://your-backend.onrender.com

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/v1/auth/login | No | Get JWT token |
| GET | /api/v1/auth/me | Yes | Current user info |
| POST | /api/v1/auth/register | Admin key | Create user |
| GET | /api/v1/auth/users | Admin | List all users |
| GET | /api/v1/auth/audit-logs | Admin | Audit trail |
| POST | /api/v1/scan/quick | Optional | Single target scan |
| POST | /api/v1/scan/batch | Operator+ | Batch scan (async) |
| GET | /api/v1/history/ | Yes | Scan history |
| GET | /api/v1/history/stats/summary | Yes | History stats |
| GET | /api/v1/health | No | Health check |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | qs-jwt-secret-2026 | JWT signing key — CHANGE IN PRODUCTION |
| `ADMIN_REGISTER_KEY` | qs-admin-key-2026 | Key required to create new users |
| `DATABASE_URL` | sqlite:///./quantumshield.db | Database URL |

---

## Keep Render Backend Alive (Free Tier)

Sign up at uptimerobot.com → Monitor:
- URL: `https://your-backend.onrender.com/api/v1/health`
- Interval: Every 5 minutes
- This prevents the 30-second cold start.

---

## Tech Stack

- **Backend:** Python 3.11 + FastAPI + SQLAlchemy + SQLite + JWT
- **Frontend:** React 18 + Vite
- **Auth:** bcrypt passwords + HS256 JWT (8 hour expiry)
- **DB:** SQLite (dev/free tier) — swap `DATABASE_URL` for PostgreSQL
- **PQC:** NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
