"""Command-line interface for the intrusion detection system."""

import argparse
import json
from pathlib import Path

from .analyzer import read_pcap
from .detectors import run_detectors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a PCAP for suspicious network behavior.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze a .pcap or .pcapng file")
    analyze.add_argument("pcap", type=Path, help="path to the packet capture")
    analyze.add_argument("--json", dest="json_path", type=Path, help="also save alerts as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.pcap.exists():
        print(f"Capture not found: {args.pcap}")
        return 2

    flows = read_pcap(args.pcap)
    alerts = run_detectors(flows)
    print(f"Analyzed {args.pcap} -> {len(flows)} flows")
    if not alerts:
        print("No suspicious behavior detected by the built-in rules.")
    else:
        print(f"Alerts: {len(alerts)}")
        for number, alert in enumerate(alerts, start=1):
            target = f" -> {alert.destination_ip}" if alert.destination_ip else ""
            print(f"{number}. [{alert.severity.upper()}] {alert.detector}: {alert.source_ip}{target}")
            print(f"   {alert.message}")
            print(f"   Evidence: {json.dumps(alert.evidence, sort_keys=True)}")

    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps([alert.as_dict() for alert in alerts], indent=2), encoding="utf-8")
        print(f"Saved JSON report to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
