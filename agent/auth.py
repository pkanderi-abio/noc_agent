from sqlalchemy.orm import Session
from agent.db import User
from passlib.context import CryptContext
from typing import Dict, Optional
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends
from agent.db import get_db

SECRET_KEY = "gHKhj5gTod5C_W24u3kCo9k5mVEenXwysdy"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def role_required(role: str):
    def role_checker(user: Dict = Security(get_current_user)):
        if role not in user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires {role} role"
            )
        return user
    return role_checker

def authenticate_user(username: str, password: str, db: Session) -> Optional[Dict]:
    user = db.query(User).filter_by(username=username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):  # type: ignore
        return None
    return {"username": username, "roles": [r.name for r in user.roles]}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "sub": data.get("sub"), "roles": data.get("roles", [])})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Security(oauth2_scheme), db: Session = Depends(get_db)) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        roles: list[str] = payload.get("roles", [])
        if username is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Could not validate credentials")
    if db is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database session not provided")
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    # Fetch roles directly from the database
    roles = [r.name for r in user.roles]
    return {"username": username, "roles": roles}

