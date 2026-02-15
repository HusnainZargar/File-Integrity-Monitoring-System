# File Integrity Monitoring (FIM) System for Linux

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)
![Framework](https://img.shields.io/badge/Web-Flask-lightgrey)
![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)

> **Status:** 🚧 Under Development  
> **Release:** v0.3.0-alpha

---

## Overview

A lightweight **File Integrity Monitoring (FIM)** tool for Linux that detects **real-time file content and metadata changes** using kernel-level notifications.  
Built for **learning, research, and security tooling demonstrations**, with a modern web dashboard for visibility.

The goal is to provide a **simple, event-driven FIM tool** suitable for:
- Cybersecurity learning
- Academic projects
- Home lab security monitoring

---

## Objectives

- Detect file integrity violations in real time
- Avoid resource-heavy polling mechanisms
- Maintain a baseline of file attributes including SHA-256 hashes, ownership, permissions, and more
- Log and visualize integrity alerts through a web interface
- Run silently as a background service on Linux

---

## ✨ Key Features

### Directory Monitoring
- User-defined directories monitored recursively
- Supports dynamic addition of new directories

### Event-Based Detection
- Uses Linux kernel notifications via **pyinotify**
- Detects:
  - File creation
  - File modification
  - File deletion
  - Metadata changes (`IN_ATTRIB`)
  - Move / rename events

### Baseline Management
- SQLite-based persistent baseline
- Stores comprehensive file attributes:
  - SHA-256 hash
  - Owner
  - Group
  - Permissions (mode)
  - SUID/SGID
  - File size
  - Modification time (mtime)

### Alert Logging
- Timestamped alerts stored in SQLite
- Detailed JSON payloads containing:
  - Old vs new attributes
  - Change context (what changed and how)

### Web Dashboard (Flask)
- Modern dark-themed UI
- Separate views for **Logs** and **Alerts**
- Expandable alert rows with:
  - Side-by-side attribute comparison
  - Highlighted changed fields
- Severity indicators:
  - Critical
  - High
  - Medium
  - Low
 
### Enhanced Change Detection
- Detects both content and metadata changes
- Tracks ownership, permissions, group, SUID, size, and timestamps

### Move / Rename Handling
- Supports move/rename detection using:
  - `IN_MOVED_FROM`
  - `IN_MOVED_TO`
- Correlates move events into a single logical alert

### Background Execution
- Runs as a **systemd service**
- Persistent monitoring across reboots

---

## 🛠️ Technology Stack

| Component       | Technology |
|-----------------|-----------|
| Language        | Python |
| Monitoring      | pyinotify |
| Hashing         | SHA-256 |
| Web UI          | Flask + Jinja templating |
| Styling         | Custom CSS (dark theme) |
| Storage         | SQLite |
| Operating System| Linux (tested on Kali Linux) |

---

## Methodology

### Configuration
- Directories specified via CLI arguments
- systemd service for background execution

### Initial Baseline Scan
- Recursively walks the target directory
- Captures full file attributes into baseline

### Real-Time Monitoring
- Kernel filesystem events trigger integrity checks
- Supports modify, create, delete, attrib, and move events

### Alert Processing
- Compares current attributes with baseline
- Categorizes alerts:
  - File Modified
  - Permission Change
  - Ownership Change
  - SUID Change
  - File Deleted
  - New File Detected

### Web Interface
- Flask routes:
  - `/logs` — operational and event logs
  - `/alerts` — integrity alerts
- Responsive dashboard with expandable alert details

### Deployment
- Automated systemd service creation and management
---

## Current Scope (MVP)

✔ Linux-only support  
✔ Single-host monitoring  
✔ Local DB baseline  
✔ Basic alert dashboard  

❌ No notification system  
❌ No encrypted baseline  
❌ No distributed agents  

---

## Planned Enhancements

- Email alerts
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
