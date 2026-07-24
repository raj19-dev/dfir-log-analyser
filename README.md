<div align="center">


<br/>

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-4F8CFF?style=for-the-badge&logo=python&logoColor=white)
![Rich](https://img.shields.io/badge/CLI-Rich-32C48D?style=for-the-badge&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0-blueviolet?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

<br/>

> **A Python-based DFIR tool that ingests raw tcpdump log files, automatically correlates network events into connections, classifies them as Normal / Suspicious / Malicious, and surfaces attack patterns — available as both a CLI tool and a desktop GUI dashboard.**

</div>

---

## 📸 Dashboard

![DFIR Log Analyser Dashboard](assets/screenshot.png)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔗 **Event Correlation Engine** | Groups raw log entries into bidirectional connections by IP pair and port — the core technical innovation |
| 🔴 **SYN Flood Detection** | Identifies high-volume SYN packet floods with no completed TCP handshake |
| 🟡 **ICMP Flood Detection** | Flags abnormal volumes of ICMP packets from a single source |
| 🔀 **Traffic Redirect Detection** | Correlates DNS resolutions against actual connections to detect suspicious redirects |
| 🖥️ **Desktop GUI Dashboard** | Full CustomTkinter dashboard with summary cards, connection table, search, severity filters, and a detail panel |
| ⌨️ **CLI Mode** | Rich-powered terminal output for analysts who prefer command line |
| 📤 **JSON Export** | Export full analysis results to a structured JSON report |
| 📋 **Connection Detail Panel** | Click any connection to inspect its packet-level evidence and timeline |
| 🔍 **Search & Filter** | Filter by severity (Malicious / Suspicious / Normal) or search by IP, port, or reason |

---

## 🛡️ Detection Logic

### SYN Flood
Triggered when a single source sends **10+ SYN packets** to the same destination with **no completed TCP handshakes** (no ACK completion). Consistent with volumetric DoS attacks.

### ICMP Flood
Triggered when **10+ ICMP packets** are detected from a single source. Consistent with ping flood / DDoS amplification attacks.

### Traffic Redirect
Uses **DNS correlation** — the tool tracks DNS query/response pairs using query IDs, builds a domain→IP map, then checks whether subsequent TCP connections go to the expected resolved IP. A mismatch indicates a possible redirect, spoofing, or malware-induced domain hijack.

---

## 🗂️ Project Structure

```
dfir-log-analyser/
│
├── analyser.py         # CLI entry point (argparse)
├── gui.py              # GUI entry point (CustomTkinter dashboard)
├── parser.py           # tcpdump log parser — multiline support + DNS correlation
├── correlator.py       # Event grouping engine — bidirectional connection keys
├── classifier.py       # Attack detection — SYN flood, ICMP flood, redirect
├── reporter.py         # CLI output (Rich) + JSON export
├── models.py           # Data structures — Event and Connection dataclasses
│
├── sample_logs/        # Sample tcpdump logs for testing
│   ├── syn_flood.txt
│   ├── syn_flood_attack.txt
│   └── icmp_flood.txt
│
├── assets/
│   └── screenshot.png
│
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+

### Installation

```bash
# Clone the repository
git clone https://github.com/raj19-dev/dfir-log-analyser.git
cd dfir-log-analyser

# Install dependencies
pip install -r requirements.txt
```

### Run the GUI

```bash
python gui.py
```

1. Click **Browse log** to select a tcpdump `.txt` or `.log` file
2. Click **Analyse**
3. Results appear in the dashboard — click any row to inspect packet-level evidence
4. Click **Export JSON** to save the report

### Run the CLI

```bash
python analyser.py sample_logs/syn_flood_attack.txt
```

With JSON export:

```bash
python analyser.py sample_logs/syn_flood_attack.txt --export
```

---

## 📦 Dependencies

| Library | Purpose |
|---------|---------|
| `customtkinter` | Modern desktop GUI framework |
| `rich` | Beautiful CLI output — tables, panels, colour coding |

Install all:
```bash
pip install -r requirements.txt
```

---

## 🧪 Sample Logs

Three sample logs are included for testing:

| File | Contains |
|------|---------|
| `syn_flood.txt` | DNS redirect scenario — yummyrecipesforme.com brute force case |
| `syn_flood_attack.txt` | SYN flood from single attacker IP |
| `icmp_flood.txt` | ICMP flood from single attacker IP |

---

## 📈 Version History

| Version | Highlights |
|---------|-----------|
| **v1.0** | Correlation engine, SYN flood + ICMP flood + redirect detection, CLI + GUI |

---

## 🔮 Planned — v2.0

- [ ] Wireshark CSV format support
- [ ] Confidence scoring per detection (0–100%)
- [ ] Auto-generated NIST CSF incident report from analysis results
- [ ] Live packet capture mode via Scapy

---

## 👨‍💻 Author

**Rajdeep Ganguly**  
B.Tech Cybersecurity Student 

[![GitHub](https://img.shields.io/badge/GitHub-raj19--dev-181717?style=flat-square&logo=github)](https://github.com/raj19-dev)
[![Blog](https://img.shields.io/badge/Blog-rajdeepcyber.wordpress.com-21759B?style=flat-square&logo=wordpress&logoColor=white)](https://rajdeepcyber.wordpress.com)
[![Gmail](https://img.shields.io/badge/Email-gangulyrajdeep482-D14836?style=flat-square&logo=gmail&logoColor=white)](mailto:gangulyrajdeep482@gmail.com)

---

<div align="center">

⭐ **If you found this useful, consider starring the repo!**


</div>
