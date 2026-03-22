"""
QuantumShield — Database Configuration
SQLite for dev/free-tier, easy swap to PostgreSQL for production.
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./quantumshield.db")

# SQLite needs check_same_thread=False
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Models ────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id          = Column(Integer, primary_key=True, index=True)
    username    = Column(String(50), unique=True, index=True, nullable=False)
    email       = Column(String(100), unique=True, index=True, nullable=False)
    hashed_pw   = Column(String(200), nullable=False)
    role        = Column(String(20), default="Viewer")   # Admin | Operator | Checker | Viewer
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login  = Column(DateTime, nullable=True)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(50), unique=True, index=True)
    user_id      = Column(Integer, nullable=True)          # null = unauthenticated
    username     = Column(String(50), nullable=True)
    target       = Column(String(255), nullable=False)
    port         = Column(Integer, default=443)
    pqc_score    = Column(Integer, nullable=True)
    pqc_status   = Column(String(30), nullable=True)
    tls_version  = Column(String(20), nullable=True)
    cipher_suite = Column(String(100), nullable=True)
    result_json  = Column(Text, nullable=True)             # full JSON blob
    scanned_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, nullable=True)
    username   = Column(String(50), nullable=True)
    action     = Column(String(50), nullable=False)        # LOGIN | LOGOUT | SCAN | EXPORT
    target     = Column(String(255), nullable=True)
    details    = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    timestamp  = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── DB Helpers ────────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables and seed default users."""
    from passlib.context import CryptContext
    Base.metadata.create_all(bind=engine)

    pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
    db  = SessionLocal()

    default_users = [
        {"username": "admin",   "email": "admin@quantumshield.io",   "role": "Admin",    "password": "quantum2026"},
        {"username": "pnb",     "email": "pnb@pnbindia.in",          "role": "Operator", "password": "pnbsecure"},
        {"username": "auditor", "email": "auditor@quantumshield.io", "role": "Checker",  "password": "audit2026"},
    ]

    for u in default_users:
        exists = db.query(User).filter(User.username == u["username"]).first()
        if not exists:
            db.add(User(
                username=u["username"],
                email=u["email"],
                hashed_pw=pwd.hash(u["password"]),
                role=u["role"],
            ))

    db.commit()
    db.close()
