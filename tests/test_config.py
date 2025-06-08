import pytest
from agent.config import Config

def test_load_default(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("scan: {targets: '1.1.1.1', ports: '80'}")
    monkeypatch.chdir(tmp_path)
    cfg = Config.load()
    assert cfg.scan['targets'] == '1.1.1.1'