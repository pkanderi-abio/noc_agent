import pytest
import asyncio
from agent.agent import scan_loop, capture_loop, NmapScanner, PacketCapture

@pytest.mark.asyncio
async def test_scan_loop_runs_once(monkeypatch):
    calls = []
    class DummyScanner(NmapScanner):
        def scan(self):
            calls.append(True)
            return {}
    dummy = DummyScanner(targets="", ports="")
    task = asyncio.create_task(scan_loop(dummy, interval=1))
    await asyncio.sleep(1.1)
    task.cancel()
    assert calls

@pytest.mark.asyncio
async def test_capture_loop_runs(monkeypatch):
    class DummyCapture(PacketCapture):
        def start(self, cb):
            cb("pkt")
    dummy = DummyCapture(iface=None, bpf_filter=None, count=1)
    packets = []
    def cb(p): packets.append(p)
    await capture_loop(dummy, cb)
    assert packets == ["pkt"]