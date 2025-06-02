# 🔐 Local Network Vulnerability Scanner (GUI)

A Python-based GUI tool that scans local network devices, detects open ports, identifies running protocols, and flags common security vulnerabilities — all in a user-friendly interface.

---

## ⚙️ Features

- 📡 **Device Discovery** (via ARP)
- 🔍 **Port Scanning** (using `nmap`)
- 🧠 **Protocol Identification**
- 🚨 **Vulnerability Alerts**
- 🖥️ **Graphical User Interface** (Built with `Tkinter`)
- 🚀 **Multi-threaded** for smooth, non-blocking scans

---

## 🔧 Requirements

- Python 3.8+
- Admin/Sudo access (for low-level network operations)

### 📦 Dependencies

Install the required Python libraries using pip:

```bash
pip install scapy python-nmap
