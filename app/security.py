from dataclasses import dataclass
from typing import Optional, Dict

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


# Demo "database" (replace with SQLite later)
USERS_DB: Dict[str, dict] = {
    "admin": {"password": "admin123", "role": "admin"},
    "eric": {"password": "password123", "role": "user"},
}

# Demo token store: token -> username (replace with signed JWT later)
TOKENS: Dict[str, str] = {}

auth_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    username: str
    role: str


def create_demo_token(username: str) -> str:
    # Simple deterministic token for demo only (NOT secure)
    return f"demo-token-{username}"


def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(auth_scheme),
) -> CurrentUser:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    token = creds.credentials
    username = TOKENS.get(token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return CurrentUser(username=username, role=user["role"])


def require_role(required_role: str):
    def _checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required_role}",
            )
        return user

    return _checker
