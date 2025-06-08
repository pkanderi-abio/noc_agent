# File: agent/auth.py
import os
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
from fastapi import HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer

# Secret key (in prod, load from env)
SECRET_KEY = os.getenv("NOC_SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dummy user store
_USERS = {
    "admin": {
        "password": "admin123",
        "roles": [
            "admin","train_anomaly","infer_anomaly",
            "train_threat","infer_threat",
            "train_nlp","infer_logs"
        ]
    }
}

def authenticate_user(username: str, password: str) -> Optional[Dict]:
    user = _USERS.get(username)
    if not user or user.get("password") != password:
        return None
    return {"username": username, "roles": user["roles"]}

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "sub": data.get("sub")})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Security(oauth2_scheme)) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        roles = payload.get("roles", [])
        if username is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not validate credentials")
    user = _USERS.get(username)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return {"username": username, "roles": roles}
