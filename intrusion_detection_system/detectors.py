"""Simple, explainable detection rules for PCAP-derived flows."""

from collections import defaultdict

from .models import Alert, Flow


def detect_port_scans(flows: list[Flow], minimum_ports: int = 8) -> list[Alert]:
    ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    for flow in flows:
        if flow.destination_port is not None:
            ports[(flow.source_ip, flow.destination_ip)].add(flow.destination_port)

    alerts = []
    for (source, destination), values in ports.items():
        if len(values) >= minimum_ports:
            alerts.append(Alert(
                detector="port_scan",
                severity="high",
                score=85,
                source_ip=source,
                destination_ip=destination,
                message=f"Host contacted {len(values)} different ports on one destination.",
                evidence={"unique_ports": sorted(values), "threshold": minimum_ports},
            ))
    return alerts


def detect_syn_bursts(flows: list[Flow], minimum_attempts: int = 10) -> list[Alert]:
    attempts: dict[tuple[str, str, int | None], int] = defaultdict(int)
    for flow in flows:
        attempts[(flow.source_ip, flow.destination_ip, flow.destination_port)] += flow.syn_count

    alerts = []
    for (source, destination, port), count in attempts.items():
        if count >= minimum_attempts:
            alerts.append(Alert(
                detector="connection_burst",
                severity="medium",
                score=65,
                source_ip=source,
                destination_ip=destination,
                message=f"Repeated TCP connection attempts targeted port {port}.",
                evidence={"syn_attempts": count, "threshold": minimum_attempts, "destination_port": port},
            ))
    return alerts


def detect_dns_anomalies(flows: list[Flow], minimum_domains: int = 10) -> list[Alert]:
    domains: dict[str, set[str]] = defaultdict(set)
    for flow in flows:
        domains[flow.source_ip].update(flow.dns_queries)

    alerts = []
    for source, values in domains.items():
        if len(values) >= minimum_domains:
            alerts.append(Alert(
                detector="dns_anomaly",
                severity="medium",
                score=55,
                source_ip=source,
                destination_ip=None,
                message=f"Host queried {len(values)} unique DNS names in the capture.",
                evidence={"unique_domains": sorted(values), "threshold": minimum_domains},
            ))
    return alerts


def run_detectors(flows: list[Flow]) -> list[Alert]:
    """Run all built-in detectors and return alerts sorted by score."""
    alerts = []
    alerts.extend(detect_port_scans(flows))
    alerts.extend(detect_syn_bursts(flows))
    alerts.extend(detect_dns_anomalies(flows))
    return sorted(alerts, key=lambda alert: alert.score, reverse=True)
