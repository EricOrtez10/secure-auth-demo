import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# ---------------------------
# Config (demo-safe defaults)
# ---------------------------
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# IMPORTANT:
# For real projects, NEVER hardcode secrets.
# For this demo, we allow a fallback if env var isn't set.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me-please")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------
# Demo "database"
# Store HASHED passwords only
# ---------------------------
USERS_DB: Dict[str, dict] = {
    "admin": {"hashed_password": "$2b$12$qzse7jRlVNDY9ivoUyFkgOD1Z7alNUnj8jnPmJznXTSoKt.hz.nMi", "role": "admin"},
    "eric": {"hashed_password": "$2b$12$cxYLc1YNhxBuMARMPgpl6e4aseCPRx.NdU2t4tXl4.H4o70AZdx0W", "role": "user"},
}

# HTTP Bearer auth scheme (adds the Authorization: Bearer <token> behavior)
auth_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    username: str
    role: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str) -> Optional[CurrentUser]:
    user = USERS_DB.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return CurrentUser(username=username, role=user["role"])


def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme),
) -> CurrentUser:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    token = creds.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if not username or not role:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        return CurrentUser(username=username, role=role)

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def require_role(required_role: str):
    def _role_guard(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _role_guard

