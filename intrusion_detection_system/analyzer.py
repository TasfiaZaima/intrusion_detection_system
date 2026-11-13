"""Read packets from a PCAP and turn them into simple flow records."""

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader

from .models import Flow


def read_pcap(path: str | Path) -> list[Flow]:
    """Return one Flow per source/destination/protocol/port combination."""

    grouped: dict[tuple, Flow] = {}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if IP not in packet:
                continue

            ip = packet[IP]
            source_port = destination_port = None
            protocol = str(ip.proto)
            syn = 0

            if TCP in packet:
                protocol = "TCP"
                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)
                syn = int(bool(packet[TCP].flags & 0x02) and not bool(packet[TCP].flags & 0x10))
            elif UDP in packet:
                protocol = "UDP"
                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)
            elif ip.proto == 1:
                protocol = "ICMP"

            key = (ip.src, ip.dst, source_port, destination_port, protocol)
            if key not in grouped:
                grouped[key] = Flow(
                    timestamp=float(getattr(packet, "time", 0.0)),
                    source_ip=ip.src,
                    destination_ip=ip.dst,
                    source_port=source_port,
                    destination_port=destination_port,
                    protocol=protocol,
                )

            flow = grouped[key]
            flow.packet_count += 1
            flow.byte_count += len(packet)
            flow.syn_count += syn

            if DNS in packet and packet[DNS].qdcount and DNSQR in packet:
                query = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                if query and query not in flow.dns_queries:
                    flow.dns_queries.append(query)

    return list(grouped.values())
