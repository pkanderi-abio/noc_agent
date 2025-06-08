```
NOC-AGENT
```
Network Operations Center (NOC) Agent
A cross-platform, AI-driven network monitoring and analysis agent that provides:
Network Scanning via nmap (python-nmap)
Packet Capture & Analysis via scapy
Anomaly Detection using IsolationForest
Threat Classification using RandomForestClassifier
Log Analysis via a lightweight summarization stub (extendable)
REST API powered by FastAPI with OAuth2 authentication
Metrics Endpoint for Prometheus integration
CLI entry point noc-agent for local or server modes
Features
Agent Mode: Runs continuous scans and packet captures
Server Mode: Exposes HTTP endpoints for scan, training, inference, and metrics
Cross-Platform: Supports Linux, macOS, and Windows
Packaging: Installable via pip with a console script
Service Definitions: Systemd (Linux), launchd (macOS), NSSM (Windows)
AI/ML: Easily train and run Isolation Forest, Random Forest, and (future) NLP models
Installation
# From PyPI or local wheel into a virtual environment or globally
pip install noc_agent
To avoid permission issues on macOS/Linux, install into a virtualenv:
python3 -m venv .venv
source .venv/bin/activate
pip install noc_agent
Development mode:
•
•
•
•
•
•
•
•
•
•
•
•
•
•
1
git clone https://github.com/yourrepo/noc_agent.git
cd noc_agent
# Edit code freely, then install in editable mode
pip install -e .
Configuration
Create a config.yaml file:
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
Set the env var before running:
export CONFIG_PATH=/path/to/config.yaml
Quickstart
Server Mode
noc-agent --mode server
GET /health : Health check
POST /token : OAuth2 password flow
POST /scan : Trigger network scan
POST /train/anomaly|threat|logs : Train models
POST /infer/anomaly|threat : Get inference results
POST /analyze/logs : Summarize logs
GET /metrics : Prometheus metrics
•
•
•
•
•
•
•
2
Agent Mode
noc-agent --mode agent
Continuously performs scans and packet captures, logging outputs.
CLI Usage
Once installed, the noc-agent command should be available in your PATH :
which noc-agent # e.g. ~/.venv/bin/noc-agent or /usr/local/bin/noc-agent
noc-agent --help
If for some reason the console script isn’t installed or you see a StopIteration error, you can invoke
directly via Python:
python -m agent.agent --mode help
"```
Or run agent mode:
```bash
python -m agent.agent --mode agent
And server mode:
python -m agent.agent --mode server
This bypasses any entry-point issues and ensures you’re running the correct CLI logic.