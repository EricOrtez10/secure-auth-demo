
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel

from app.security import USERS_DB, TOKENS, create_demo_token, get_current_user, require_role, CurrentUser

app = FastAPI(title="Secure Auth Demo App")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"message": "Secure Auth Demo App running"}


@app.post("/login")
def login(payload: LoginRequest):
    user = USERS_DB.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_demo_token(payload.username)
    TOKENS[token] = payload.username
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.get("/me")
def me(user: CurrentUser = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@app.get("/admin")
def admin_only(user: CurrentUser = Depends(require_role("admin"))):
    return {"message": f"Welcome admin: {user.username}"}
