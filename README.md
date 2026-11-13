# Intrusion Detection System

Intrusion Detection System is a small, explainable security tool for analyzing network traffic. It is designed as a practical learning project: the code is split into understandable modules, the rules are easy to adjust, and every alert explains the evidence that caused it.

## Project overview

The Intrusion Detection System reads `.pcap` or `.pcapng` files with Scapy, summarizes packets into network flows, and runs three built-in detectors:

- **Port scan detection:** finds a source contacting many different destination ports on one host.
- **Connection burst detection:** finds repeated TCP SYN attempts to the same service.
- **DNS anomaly detection:** finds a source querying many unique DNS names.

The output includes a severity, risk score, affected hosts, and evidence. This is a metadata-based IDS, so it can still find behavioral signals in encrypted traffic, but it does not decrypt payloads.

## How intrusion detection works

The current version does **not** use a machine-learning model. It uses simple, explainable behavioral rules so that every alert can be understood and tested easily.

The system extracts packet metadata, groups packets into flows, and applies these thresholds:

- **Port scan:** one source contacts at least 8 different ports on one destination.
- **Connection burst:** at least 10 TCP SYN attempts target the same service.
- **DNS anomaly:** one host queries at least 10 unique DNS names in the capture.

Every alert includes its detector name, severity, risk score, affected hosts, explanation, and supporting evidence. An ML detector, such as Isolation Forest, could be added later for detecting behavior that differs from a learned normal baseline, but it is intentionally not required in this beginner-friendly version.

## Requirements

- Python 3.10 or newer
- A `.pcap` or `.pcapng` capture collected in an authorized lab or network

## Installation

From the project directory:

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
python -m pip install -e ".[dev]"
```

## Run the IDS

Analyze a capture:

```bash
python -m intrusion_detection_system.cli analyze path/to/capture.pcap
```

Save the alerts as JSON as well:

```bash
python -m intrusion_detection_system.cli analyze path/to/capture.pcap --json reports/alerts.json
```

The same command is available after installation:

```bash
ids analyze path/to/capture.pcap
```

The JSON output is useful for later dashboard or SIEM integration. The command only reads the capture; it does not send packets or modify the network.

## Run tests

```bash
pytest
```

## Project layout

```text
intrusion_detection_system/
├── analyzer.py       # PCAP reading and flow creation
├── detectors.py      # explainable detection rules
├── models.py         # Flow and Alert data structures
└── cli.py            # command-line interface
tests/
└── test_detectors.py
```

## Adjusting detection sensitivity

The thresholds are ordinary function arguments in `intrusion_detection_system/detectors.py`. For example, a lab with short captures may use a lower port-scan threshold:

```python
detect_port_scans(flows, minimum_ports=5)
```

In a future version, these values can be moved into a YAML configuration file and live interface monitoring can be added without changing the detectors.

## Limitations

This is an educational, PCAP-based IDS rather than a production replacement for Suricata or Zeek. It currently focuses on IPv4 metadata, uses simple thresholds, and does not inspect application payloads. Thresholds should be tuned for the environment to reduce false positives.
