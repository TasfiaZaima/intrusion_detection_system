"""Small data structures shared by the analyzer and detectors."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Flow:
    """A compact summary of traffic from one source to one destination."""

    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    dns_queries: list[str] = field(default_factory=list)


@dataclass
class Alert:
    detector: str
    severity: str
    score: int
    source_ip: str
    destination_ip: str | None
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
