from datetime import datetime, timedelta
from typing import List
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from agent.db import SessionLocal, init_db, User, Role
from agent.config import Config

# OAuth2 setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
cfg = Config.load()

# Initialize DB on import
init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authenticate against DB
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter_by(username=username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return None
    return user

# JWT

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        cfg.auth.get('oauth2_secret_key'),
        algorithm=cfg.auth.get('oauth2_algorithm')
    )

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            cfg.auth.get('oauth2_secret_key'),
            algorithms=[cfg.auth.get('oauth2_algorithm')]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise credentials_exception
    return user

async def role_required(required: str, current_user: User = Depends(get_current_user)):
    # check RBAC
    allowed = []
    for role in current_user.roles:
        permissions = cfg.rbac.get('roles', {}).get(role.name, [])
        allowed.extend(permissions)
    if required not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation '{required}' not permitted"
        )
    return current_user

def role_required(required_permission: str):
    """
    Returns a FastAPI dependency that enforces the given permission.
    """
    async def checker(current_user = Depends(get_current_user)):
        # current_user.roles is a list of Role objects
        permissions = []
        for role in current_user.roles:
            permissions += cfg.rbac.get('roles', {}).get(role.name, [])
        if required_permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation '{required_permission}' not permitted"
            )
        return current_user
    return checker