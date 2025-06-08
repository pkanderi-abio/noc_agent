import pytest
from agent.capture import PacketCapture

@pytest.fixture
def capture():
    return PacketCapture(iface=None, bpf_filter="icmp", count=1)

def test_capture_attributes(capture):
    assert capture.iface is None
    assert capture.bpf_filter == "icmp"
    assert capture.count == 1

@pytest.mark.skip(reason="Requires root privileges and live network")
def test_start_capture(capture):
    # This will sniff a single packet, ensure callback invoked
    invoked = []
    def cb(pkt): invoked.append(pkt)
    capture.start(cb)
    assert invoked