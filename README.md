# Network Intrusion Detection System (NIDS) — Minor Project

## Author & Acknowledggments

* **Author:** Laxman Narvenkar
* **Degree:** M.Sc. Cyber Security
* **Institution:** National Forensic Sciences University (NFSU)
* **Project Type:** Academic Minor Project

## System Requirements

* **Operating System:** Windows 10/11 or Linux (Kali / Ubuntu)
* **Python Version:** Python 3.10 or higher
* **Required Libraries:** `scapy`, `matplotlib`, `tkinter`
* **Driver Requirements:** Npcap (Windows) or root access (Linux) for raw packet capturing

## Tech Stack

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python)
![Scapy](https://img.shields.io/badge/Traffic%20Analysis-Scapy-red?style=flat)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green?style=flat)
![VirtualBox](https://img.shields.io/badge/Lab-VirtualBox%20%2B%20Kali-orange?style=flat&logo=virtualbox)

## Future Roadmap

- [ ] Add machine learning model integration for anomaly-based detection.
- [ ] Implement automated email / Webhook alerts for `HIGH` severity threats.
- [ ] Support PCAP file upload for offline forensic analysis.



## Run (one-click)
- **Windows:** double-click `run_nids.bat` (run Command Prompt as Administrator if capture fails)
- **Linux/macOS:** `bash run_nids.sh` (use `sudo bash run_nids.sh` if capture fails)

## Run (manual)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python code/nids_main.py --iface <iface> --log-dir logs
```

## System Architecture & Diagrams

### 1. High-Level System Architecture
![System Architecture Diagram](assets/System%20Architecture%20Diagram.png)

---

### 2. Detection Logic & Sequence Flow

| Detection Logic Flowchart | Incident Response Sequence Diagram |
| :---: | :---: |
| ![Flowchart Diagram](assets/Flowchart%20Diagram.png) | ![Sequence Diagram of Intrusion Detection Process](assets/Sequence%20Diagram%20of%20Intrusion%20Detection%20Process.png) |

---

### 3. Structural & Functional Modeling

| System Class Diagram | Actor Use Case Diagram |
| :---: | :---: |
| ![Class Diagram of the Proposed Network Intrusion Detection System](assets/Class%20Diagram%20of%20the%20Proposed%20Network%20Intrusion%20Detection%20System.png) | ![Use Case Diagram of the Network Intrusion Detection System](assets/Use%20Case%20Diagram%20of%20the%20Network%20Intrusion%20Detection%20System.png) |

## Outputs
Alerts -> `logs/alerts.jsonl` and `logs/alerts.csv`

## Project Showcase

### SentinelNIDS GUI Dashboard
![SentinelNIDS Dashboard](assets/gui_dashboard.png)

### Real-Time Attack Simulation & Detection
![Attack Simulation](assets/attack_simulation.png)

### Modular Code Architecture
![Project Structure](assets/project_structure.png)

### Structured Alert Logs (`alerts.jsonl`)
![Alert Logs](assets/alert_logs.png)

### VirtualBox Host-Only Network Setup
![Network Configuration](assets/vbox_network_config.png)

Generated: 2026-01-15 08:29
