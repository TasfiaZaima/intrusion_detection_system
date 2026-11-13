from intrusion_detection_system.detectors import detect_port_scans, detect_syn_bursts
from intrusion_detection_system.models import Flow


def flow(port: int, syn_count: int = 1) -> Flow:
    return Flow(1.0, "10.0.0.5", "10.0.0.10", 40000, port, "TCP", syn_count=syn_count)


def test_detects_port_scan():
    alerts = detect_port_scans([flow(port) for port in range(20, 28)])
    assert len(alerts) == 1
    assert alerts[0].detector == "port_scan"


def test_detects_connection_burst():
    alerts = detect_syn_bursts([flow(22, syn_count=10)])
    assert len(alerts) == 1
    assert alerts[0].evidence["syn_attempts"] == 10


def test_ignores_small_port_activity():
    assert detect_port_scans([flow(80), flow(443)]) == []
