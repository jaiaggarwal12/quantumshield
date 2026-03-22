"""
QuantumShield — Authentication Router
JWT-based auth with SQLite user store.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from typing import Optional
import os

from app.database import get_db, User, AuditLog

SECRET_KEY  = os.getenv("SECRET_KEY", "qs-jwt-secret-2026-change-in-prod-plz")
ALGORITHM   = "HS256"
TOKEN_HOURS = 8

pwd_ctx       = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
router        = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    role: str
    email: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Viewer"
    admin_key: str  # must match ADMIN_REGISTER_KEY env var

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

class PasswordChange(BaseModel):
    current_password: str
    new_password: str


# ── Helpers ───────────────────────────────────────────────────────────────────
def make_token(data: dict) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({**data, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Optional[User]:
    """Returns current user or None (for optional auth endpoints)."""
    if not token:
        return None
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        return user
    except JWTError:
        return None


def require_auth(user: Optional[User] = Depends(get_current_user)) -> User:
    """Raises 401 if not authenticated."""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(user: User = Depends(require_auth)) -> User:
    if user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_operator_or_admin(user: User = Depends(require_auth)) -> User:
    if user.role not in ("Admin", "Operator"):
        raise HTTPException(status_code=403, detail="Operator or Admin access required")
    return user


def log_action(db: Session, user: Optional[User], action: str, target: str = None,
               details: str = None, ip: str = None):
    db.add(AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "anonymous",
        action=action,
        target=target,
        details=details,
        ip_address=ip,
    ))
    db.commit()


# ── Endpoints ─────────────────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username, User.is_active == True).first()
    if not user or not pwd_ctx.verify(form.password, user.hashed_pw):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    log_action(db, user, "LOGIN", ip=request.client.host if request.client else None)

    token = make_token({"sub": user.username, "role": user.role})
    return Token(access_token=token, token_type="bearer",
                 username=user.username, role=user.role, email=user.email)


@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    """Create a new user. Requires admin key for security."""
    admin_key = os.getenv("ADMIN_REGISTER_KEY", "qs-admin-key-2026")
    if payload.admin_key != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if payload.role not in ("Admin", "Operator", "Checker", "Viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_pw=pwd_ctx.hash(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/me")
def me(user: User = Depends(require_auth)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_at": user.created_at.isoformat(),
    }


@router.post("/change-password")
def change_password(payload: PasswordChange,
                    user: User = Depends(require_auth),
                    db: Session = Depends(get_db)):
    if not pwd_ctx.verify(payload.current_password, user.hashed_pw):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user.hashed_pw = pwd_ctx.hash(payload.new_password)
    db.commit()
    log_action(db, user, "PASSWORD_CHANGE")
    return {"message": "Password updated successfully"}


@router.get("/users", dependencies=[Depends(require_admin)])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id":u.id,"username":u.username,"email":u.email,"role":u.role,
             "is_active":u.is_active,"created_at":u.created_at,"last_login":u.last_login}
            for u in users]


@router.get("/audit-logs", dependencies=[Depends(require_admin)])
def get_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [{"id":l.id,"username":l.username,"action":l.action,"target":l.target,
             "details":l.details,"ip_address":l.ip_address,"timestamp":l.timestamp}
            for l in logs]
