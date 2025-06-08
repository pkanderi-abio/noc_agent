import pytest
from fastapi.testclient import TestClient
from agent.config import Config
from agent.api import app

cfg = Config.load()
client = TestClient(app)

def get_token(username, password):
    resp = client.post(
        "/token",
        data={"username": username, "password": password}
    )
    assert resp.status_code == 200, "Failed to obtain token"
    return resp.json()["access_token"]

@pytest.fixture
def admin_token():
    admin_cfg = cfg.auth_defaults["initial_users"][0]
    return get_token(admin_cfg["username"], admin_cfg["password"])

def test_rbac_allowed(admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/model_info", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "model_path" in data and "contamination" in data

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

def test_metrics():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    # Should see the scan counter help text
    assert "# HELP noc_scan_count" in resp.text
