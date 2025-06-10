
import sys
print(sys.path)
import agent
print(agent.__file__)
import asyncio
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket
from fastapi.security import OAuth2PasswordRequestForm
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.orm import Session
from agent.anomaly import AnomalyDetector
from agent.config import Config
from agent.scanner import NmapScanner
from agent.capture import PacketCapture
from agent.auth import (
    create_access_token, oauth2_scheme,
    authenticate_user, get_current_user, role_required
)
from agent.db import get_db as db
from fastapi import Depends
from datetime import timedelta
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from agent.db import User, Role
from starlette.responses import Response

# Initialize password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Load config
cfg = Config.load()
ACCESS_TOKEN_EXPIRE_MINUTES = cfg.auth.get('access_token_expire_minutes')

# Metrics
SCAN_COUNT = Counter('noc_scan_count', 'Number of scan requests')
PACKET_COUNT = Counter('noc_packet_count', 'Number of packets captured')
ANOMALY_COUNT = Counter('noc_anomaly_count', 'Number of anomalies detected')

app = FastAPI(
    title="NOC Agent API",
    description="Endpoints with dynamic user management, OAuth2, RBAC, metrics, WS",
    version="0.5.0"
)

# Core instances
detector = AnomalyDetector(
    model_path=cfg.anomaly.get('model_path'),
    contamination=cfg.anomaly.get('contamination')
)

scanner = NmapScanner()  # Config is loaded in NmapScanner

capture_cfg = cfg.capture

@app.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(db)
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user["username"], "roles": user["roles"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users", dependencies=[Depends(role_required("user_manage"))])
def list_users(db: Session = Depends(db)):
    return [{"username": u.username, "roles": [r.name for r in u.roles]} for u in db.query(getattr(__import__('agent.db', fromlist=['User']), 'User')).all()]

@app.post("/users", dependencies=[Depends(role_required("user_manage"))])
def create_user(username: str, password: str, roles: list[str], db: Session = Depends(db)):
    from agent.db import User, Role
    if db.query(User).filter_by(username=username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed)
    for role_name in roles:
        role = db.query(Role).filter_by(name=role_name).first()
        if role:
            user.roles.append(role)
    db.add(user)
    db.commit()
    return {"username": user.username, "roles": [r.name for r in user.roles]}

@app.delete("/users/{username}", dependencies=[Depends(role_required("user_manage"))])
async def delete_user(username: str, db: Session = Depends(db)):
    """Delete a user account by username."""
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"status": "deleted", "username": username}

@app.post("/users/{username}/reset_password", dependencies=[Depends(role_required("user_manage"))])
async def reset_password(username: str, new_password: str, db: Session = Depends(db)):
    """Reset a user's password."""
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = pwd_context.hash(new_password)
    db.commit()
    return {"status": "password_reset", "username": username}

@app.put("/users/{username}/roles", dependencies=[Depends(role_required("user_manage"))])
async def update_roles(username: str, roles: list[str], db: Session = Depends(db)):
    """Update roles assigned to a user."""
    user = db.query(User).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # clear and set new roles
    user.roles.clear()
    for role_name in roles:
        role = db.query(Role).filter_by(name=role_name).first()
        if role:
            user.roles.append(role)
    db.commit()
    return {"status": "roles_updated", "username": username, "roles": [r.name for r in user.roles]}

# ... existing endpoints unchanged, but all secured via role_required

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/model_info")
async def model_info(user=Depends(role_required("model_info"))):
    return {
        "model_path": cfg.anomaly.get('model_path'),
        "contamination": cfg.anomaly.get('contamination')
    }

@app.post("/train")
async def train_model(
    data: list[list[float]],
    user=Depends(role_required("train"))
):
    path = detector.train(data)
    return {"status": "trained", "model_path": path}

@app.post("/infer")
async def infer(
    features: list[float],
    user=Depends(role_required("infer"))
):
    is_anomaly = detector.detect(features)
    if is_anomaly:
        ANOMALY_COUNT.inc()
    return {"anomaly": is_anomaly}

@app.post("/scan")
async def run_scan(user=Depends(role_required("scan"))):
    SCAN_COUNT.inc()
    result = scanner.scan()
    return {"scan": result}

@app.post("/capture_once")
async def capture_once(
    count: int = 1,
    user=Depends(role_required("capture"))
):
    results = []
    def cb(pkt):
        summary = pkt.summary()
        PACKET_COUNT.inc()
        results.append(summary)
    cap = PacketCapture(
        iface=capture_cfg.get('iface'),
        bpf_filter=capture_cfg.get('bpf_filter'),
        count=count
    )
    cap.start(cb)
    return {"packets": results}

@app.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(data, media_type=CONTENT_TYPE_LATEST)

@app.websocket("/ws/packets")
async def websocket_packets(ws: WebSocket, user=Depends(role_required("ws_packets"))):
    await ws.accept()
    loop = asyncio.get_event_loop()
    def cb(pkt):
        summary = pkt.summary()
        PACKET_COUNT.inc()
        asyncio.run_coroutine_threadsafe(ws.send_text(summary), loop)
    cap = PacketCapture(
        iface=capture_cfg.get('iface'),
        bpf_filter=capture_cfg.get('bpf_filter'),
        count=0
    )
    await loop.run_in_executor(None, cap.start, cb)