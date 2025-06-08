import pytest
from agent.scanner import NmapScanner

@pytest.fixture
def scanner():
    return NmapScanner(targets="127.0.0.1", ports="22")

def test_scan_returns_dict(scanner):
    result = scanner.scan(arguments="-sT -Pn")
    assert isinstance(result, dict)
    assert "scan" in result or result == {}