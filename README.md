# Python Network Traffic Anomaly Detector

[![Continuous Integration](https://github.com/ThePreacherMan/python-network-traffic-anomaly-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/ThePreacherMan/python-network-traffic-anomaly-detector/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Python-based cybersecurity tool for analyzing network traffic, detecting suspicious behavioral patterns, and generating explainable SOC-focused anomaly alerts.

## Overview

The Python Network Traffic Anomaly Detector processes structured network-flow data from CSV files and evaluates each connection using configurable security rules.

The project is designed to demonstrate practical skills in:

- Python security automation
- Network traffic analysis
- SOC alert generation
- Detection engineering
- Explainable anomaly scoring
- Secure input validation
- Automated testing
- Continuous integration

## Features

- Validated CSV network-traffic ingestion
- Structured network-flow data models
- Explainable rule-based anomaly detection
- Configurable detection thresholds
- SOC-oriented alert severity scoring
- Anomaly-only result filtering
- Human-readable terminal output
- Machine-readable JSON output
- CLI error handling
- Automated unit testing
- GitHub Actions CI across multiple Python versions

## Detection Rules

The detector currently identifies:

- High-volume data transfers
- Excessive packet counts
- Unusually high transfer rates
- Long-running network connections
- Traffic using monitored destination ports

Default monitored destination ports include:

| Port | Typical Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 445 | SMB |
| 1433 | Microsoft SQL Server |
| 3389 | Remote Desktop Protocol |
| 4444 | Common reverse-shell or backdoor port |
| 5900 | VNC |

A monitored port does not automatically prove malicious activity. It indicates that the flow may require additional investigation.

## Project Structure

```text
python-network-traffic-anomaly-detector/
├── .github/
│   └── workflows/
│       └── ci.yml
├── data/
│   └── sample_traffic.csv
├── src/
│   └── anomaly_detector/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── cli.py
│       ├── loader.py
│       ├── models.py
│       └── rules.py
├── tests/
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_loader.py
│   ├── test_models.py
│   └── test_rules.py
├── .gitignore
├── LICENSE
├── pyproject.toml
└── README.md
