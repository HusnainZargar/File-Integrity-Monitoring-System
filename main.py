import argparse
import threading
import subprocess
import os
import sys


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def banner():
    print()
    print("  ███████╗██╗███╗   ███╗")
    print("  ██╔════╝██║████╗ ████║")
    print("  █████╗  ██║██╔████╔██║")
    print("  ██╔══╝  ██║██║╚██╔╝██║")
    print("  ██║     ██║██║ ╚═╝ ██║")
    print("  ╚═╝     ╚═╝╚═╝     ╚═╝")
    print("  File Integrity Monitoring System")
    print("  v0.5.0-alpha\n")


def step(n, msg):
    print(f"  [STEP {n}] {msg}")


def info(msg):
    print(f"  [INFO]  {msg}")


def ok(msg):
    print(f"  [ OK ]  {msg}")


def warn(msg):
    print(f"  [WARN]  {msg}")


def err(msg):
    print(f"  [ERR ]  {msg}")


def separator():
    print("  " + "─" * 54)


# ─────────────────────────────────────────────────────────────
#  Systemd setup  (always runs on first/direct invocation)
# ─────────────────────────────────────────────────────────────

def setup_systemd_service(directory=None):
    separator()
    step(1, "Writing systemd unit file…")

    service_file = '/etc/systemd/system/fim.service'
    project_dir  = os.path.dirname(os.path.abspath(__file__))
    main_py_path = os.path.join(project_dir, 'main.py')
    exec_start = f"/usr/bin/python3 {main_py_path}"
    if directory:
        exec_start += f" {directory}"

    service_content = f"""[Unit]
Description=File Integrity Monitoring System
After=network.target

[Service]
User=root
WorkingDirectory={project_dir}
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    tmp = os.path.join(project_dir, 'fim.service')
    with open(tmp, 'w') as f:
        f.write(service_content)

    subprocess.run(['mv', tmp, service_file], check=True)
    ok(f"Unit file written  →  {service_file}")

    separator()
    step(2, "Reloading systemd daemon…")
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    ok("Daemon reloaded.")

    step(3, "Enabling service (auto-start on boot)…")
    subprocess.run(['systemctl', 'enable', 'fim'], check=True)
    ok("Service enabled.")

    step(4, "Starting service now…")
    subprocess.run(['systemctl', 'start', 'fim'], check=True)
    ok("Service started.")

    separator()
    print()
    print("  ┌─────────────────────────────────────────────┐")
    print("  │                                             │")
    print("  │   FIM is running as a systemd service.      │")
    print("  │                                             │")
    print("  │   Dashboard →  http://localhost:5000        │")
    print("  │   Credentials: admin / admin                │")
    print("  │                                             │")
    print("  │   Useful commands:                          │")
    print("  │     systemctl status fim                    │")
    print("  │     journalctl -u fim -f                    │")
    print("  │     systemctl stop fim                      │")
    print("  │     systemctl restart fim                   │")
    print("  │                                             │")
    print("  └─────────────────────────────────────────────┘")
    print()
    sys.exit(0)


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="File Integrity Monitoring System — initial setup / service runner"
    )
    parser.add_argument(
        'directory', type=str, nargs='?', default=None,
        help="Optional path to monitor immediately (can also add paths from the web UI)"
    )
    args = parser.parse_args()
    running_under_systemd = os.getenv('INVOCATION_ID') is not None

    if not running_under_systemd:
        # ── Direct invocation (terminal) ──────────────────────

        banner()
        separator()

        # Require root
        if os.geteuid() != 0:
            warn("This script must run as root to install the systemd service.")
            warn("Re-run with:  sudo python3 main.py" +
                 (f" {args.directory}" if args.directory else ""))
            print()
            sys.exit(1)

        if args.directory:
            path = os.path.abspath(args.directory)
            if not os.path.exists(path):
                err(f"Path does not exist: {path}")
                sys.exit(1)
            info(f"Path to monitor on first start: {path}")
        else:
            info("No path supplied — add monitored paths from the web UI Settings page.")

        separator()
        print()

        setup_systemd_service(args.directory)

    else:
        # ── Running as systemd service ─────────────────────────

        import logging
        from components.utils import get_config, set_config, add_settings_audit, init_db
        init_db()
        if args.directory:
            path = os.path.abspath(args.directory)
            paths = get_config('monitored_paths') or []
            if path not in paths:
                paths = list(paths) + [path]
                set_config('monitored_paths', paths)
                add_settings_audit(f"Systemd service added monitored path: {path}")

        set_config('monitoring_active', 1)
        from components.monitor import run_monitor_loop
        monitor_thread = threading.Thread(target=run_monitor_loop, daemon=True)
        monitor_thread.start()
        log = logging.getLogger('werkzeug')
        log.disabled = True

        from web.app import app
        app.run(host='127.0.0.1', port=5000, debug=False,
                use_reloader=False, threaded=True)
