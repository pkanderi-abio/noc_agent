noc_agent

Network Operations Center (NOC) Agent

A cross-platform, AI-driven network monitoring and analysis agent that provides:

Network Scanning via nmap

Packet Capture & Analysis via scapy

Anomaly Detection using IsolationForest

Threat Classification using RandomForestClassifier

Log Analysis via an NLP summarization stub (extendable)

REST API powered by FastAPI with OAuth2 authentication

Metrics Endpoint for Prometheus

CLI entry point noc-agent for local operations

Features

Agent Mode (runs continuous scans and feeds to central server)

Server Mode (FastAPI server providing scan/training/inference endpoints)

Cross-Platform support (Windows, macOS, Linux)

Packaging as a pip-installable package with a console script

Service Definitions for Systemd, launchd, and NSSM

Installation

# Install via pip (PyPI or local wheel)
pip install noc_agent

Prerequisites

Python 3.8+

nmap binary available in PATH

(Optional) Deep learning backend for real NLP: transformers + torch or tensorflow-macos

Quickstart

Generate a config:

# config.yaml
scan:
  targets: "192.168.1.0/24"
  ports: "1-1024"
anomaly:
  params:
    n_estimators: 100
threat:
  params:
    n_estimators: 100
paths:
  anomaly_data: "/path/to/anomaly_data.csv"
  threat_data: "/path/to/threat_data.csv"

Run the server:

export CONFIG_PATH=/path/to/config.yaml
uvicorn agent.api:app --reload --host 0.0.0.0 --port 8000

Obtain a token:

curl -X POST -F "username=admin" -F "password=password123" http://localhost:8000/token

Scan and inference:

curl -H "Authorization: Bearer <TOKEN>" -X POST http://localhost:8000/scan
curl -H "Authorization: Bearer <TOKEN>" -X POST -d '{"features": [..]}' http://localhost:8000/infer/anomaly

CLI Usage

After installation, run:

noc-agent --help

Will display commands for starting the agent in local or server mode.

Packaging & Distribution

# Build distributions
pip install build
python -m build --sdist --wheel

# Install locally
pip install dist/noc_agent-0.1.0-py3-none-any.whl

# Publish to PyPI
pip install twine
twine upload dist/*

Running as a Service

Linux: create a systemd unit in /etc/systemd/system/noc-agent.service

macOS: place the launchd plist in ~/Library/LaunchAgents

Windows: use NSSM to register the noc-agent console script

(Check the docs/ folder for full examples.)

Contributing

Fork the repo

Create a feature branch

Commit your changes

Open a PR

Please adhere to the code style and add tests under tests/.

License

This project is licensed under the MIT License—see the LICENSE file for details.

