# 🛡️ File Integrity Monitoring (FIM) System for Linux

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![Framework](https://img.shields.io/badge/Web-Flask-lightgrey)
![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)
![License](https://img.shields.io/badge/License-TBD-red)

> **Status:** 🚧 Under Development  
> **Release:** v0.1.0-alpha  
> **Scope:** Academic / Educational Security Project

---

## Overview

This project is a **lightweight File Integrity Monitoring (FIM) system** for Linux environments.  
It detects **unauthorized file changes** such as creation, modification, deletion, and movement in monitored directories.

The goal is to provide a **simple, event-driven FIM tool** suitable for:
- Cybersecurity learning
- Academic projects
- Home lab security monitoring

---

## Objectives

- Detect file integrity violations in real time
- Avoid resource-heavy polling mechanisms
- Maintain a **baseline of SHA-256 file hashes**
- Log and visualize integrity alerts through a web interface
- Run silently as a background service on Linux

---

## ✨ Key Features

- 📂 **Directory Monitoring**  
  User-defined directories are monitored for file system events

- ⚡ **Event-Based Detection**  
  Uses Linux kernel notifications via `pyinotify`

- 🧾 **Baseline Management**  
  JSON-based baseline containing SHA-256 file hashes

- 🚨 **Alert Logging**  
  Timestamped logs for detected integrity violations

- 🌐 **Web Dashboard (Flask)**  
  Displays recent file integrity alerts

- 🔁 **Background Execution**  
  Designed to run as a daemon (systemd support planned)

---

## 🛠️ Technology Stack

| Component | Technology |
|---------|-----------|
| Language | Python |
| Monitoring | pyinotify |
| Hashing | SHA-256 |
| Web UI | Flask |
| Storage | JSON |
| OS | Linux (Kali Linux tested) |

---

## Methodology

1. **Configuration**
   - Directories specified via CLI arguments

2. **Initial Baseline Scan**
   - One-time scan generates file hashes

3. **Real-Time Monitoring**
   - Kernel events trigger integrity checks

4. **Alert Processing**
   - Changes are logged and stored in memory

5. **Web Interface**
   - Flask displays integrity alerts

6. **Deployment**
   - Intended to run as a systemd service

---

## Current Scope (MVP)

✔ Linux-only support  
✔ Single-host monitoring  
✔ Local JSON baseline  
✔ Basic alert dashboard  

❌ No notification system  
❌ No encrypted baseline  
❌ No distributed agents  

---

## Planned Enhancements

- Email / Telegram alerts
- Encrypted baseline storage
- Database-backed logging
- Role-based authentication
- Cross-platform support

---

## Use Case

- Host-based intrusion detection learning
- Linux file system monitoring practice
- Academic cybersecurity projects
- Security tooling demonstrations

---

## Author

**Muhammad Husnain**  
🎓 BS Cybersecurity  
🛡️ Junior Penetration Tester  
✍️ Blog: https://hackwithhusnain.com

---

## License

License will be added once the project reaches a stable release.
