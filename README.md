# File Integrity Monitoring (FIM) System for Linux
 
[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange)](https://linux.org)
[![Framework](https://img.shields.io/badge/Web-Flask-lightgrey)](https://flask.palletsprojects.com)
[![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)]()
[![Release](https://img.shields.io/badge/Release-v0.5.0--alpha-blueviolet)]()
 
> **Status:** 🚧 Under Development &nbsp;|&nbsp; **Release:** v0.5.0-alpha
 
---
 
## Overview
 
A lightweight **File Integrity Monitoring (FIM)** tool for Linux that detects real-time file content and metadata changes using kernel-level notifications.
Built for **learning, research, and security tooling demonstrations**, with a modern dark-themed web dashboard.
 
Runs as a **systemd service** — persistent across reboots, manageable via `systemctl`.
 
---
 
## Key Features
 
- **Real-time detection** via `pyinotify` (kernel `inotify` — no polling)
- **Detects:** file creation, modification, deletion, permission changes, ownership changes, SUID changes, moves/renames
- **SHA-256 hashing** — content integrity verified on every change
- **Immutable baseline** — original snapshot preserved; every change appended to history, never overwritten
- **Per-file change history** — full attribute snapshot logged at every event
- **Severity classification** — Critical / High / Medium / Low
- **Web dashboard** — dark-themed Flask UI with:
  - Dashboard with live alert counts and Chart.js time-series + distribution charts
  - Alerts and Logs views with search and pagination
  - **File Analysis** — searchable paginated file browser with baseline diff and history timeline
  - **Statistics** — most-changed files, hourly heatmap, event type breakdown, directory breakdown, baseline drift %
  - Settings — add/remove monitored paths, exclusions, toggles, baseline rescan
  - Account — change username/password, session management
- **Systemd integration** — auto-start on boot, `journalctl` logging
- **Debounced events** — prevents alert storms on rapidly-written files
- **SQLite storage** — zero external dependencies for persistence
 
---
 
## Tech Stack
 
| Component | Technology |
|---|---|
| Language | Python 3 |
| File monitoring | pyinotify |
| Hashing | SHA-256 |
| Web UI | Flask + Jinja2 |
| Storage | SQLite |
| Styling | Custom CSS (dark theme) |
| Charts | Chart.js |
| OS | Linux (tested on Kali Linux) |
 
---
 
## Installation
 
```bash
# Clone the repo
git clone https://github.com/HusnainZargar/File-Integrity-Monitoring-System.git
cd File-Integrity-Monitoring-System
 
# Install dependencies
pip install flask pyinotify werkzeug
```
 
---
 
## Running
 
### First run — installs and starts the systemd service
 
```bash
# Without a path (add paths later from the web UI Settings page)
sudo python3 main.py
 
# With an initial path to monitor
sudo python3 main.py /etc/ssh
```
 
> ⚠️ Must be run with `sudo` — required to install the systemd unit file.
 
On first run the script will:
1. Write `/etc/systemd/system/fim.service`
2. Run `systemctl daemon-reload && systemctl enable fim && systemctl start fim`
3. Print dashboard URL and default credentials, then exit
 
The service takes over from there.
 
### Accessing the dashboard
 
```
http://localhost:5000
```
 
Default credentials: `admin` / `admin` — **change these immediately from the Account page.**
 
### Managing the service
 
```bash
systemctl status fim        # check status
systemctl stop fim          # stop
systemctl restart fim       # restart
journalctl -u fim -f        # live logs
```
 
---
 
## Project Structure
 
```
.
├── main.py                  # Entry point — systemd setup + service runner
├── components/
│   ├── monitor.py           # pyinotify event handler, baseline management
│   └── utils.py             # SQLite helpers, DB schema, file history
├── web/
│   ├── app.py               # Flask app factory
│   ├── auth.py              # Authentication (PBKDF2 hashing)
│   ├── routes.py            # All Flask routes
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       ├── alerts.html
│       ├── logs.html
│       ├── file_analysis.html
│       ├── statistics.html
│       ├── settings.html
│       ├── account.html
│       └── login.html
└── Project-Proposal.pdf
```
 
---
 
## Current Scope (v0.5.0-alpha)
 
✔ Linux-only, single-host monitoring  
✔ Systemd service with auto-start  
✔ Immutable baseline — original never overwritten  
✔ Per-file change history (append-only)  
✔ File Analysis + Statistics pages  
✔ Paginated logs, alerts, and file browser with search  
✔ Secure password hashing (PBKDF2 via werkzeug)  
✔ Event debouncing  
✔ Logout and restart confirmation modals  
 
❌ No email / push notifications  
❌ No encrypted baseline  
❌ No distributed / multi-host agents  
❌ No role-based access control  
 
---
 
## Planned Enhancements
 
- Email alerts on critical events
- Encrypted baseline storage
- Cross-platform support
- Role-based authentication
 
---
 
## Use Case
 
- Host-based intrusion detection learning
- Linux file system monitoring practice
- Academic cybersecurity projects
- Security tooling demonstrations and home-lab setups
 
---
 
## Author
 
**Muhammad Husnain**  
🎓 BS Cybersecurity &nbsp;|&nbsp; 🛡️ Junior Penetration Tester  
✍️ [hackwithhusnain.com](https://hackwithhusnain.com)
 
---
 
## License
 
MIT — see `LICENSE` for details.
