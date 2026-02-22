import argparse
import threading
import subprocess
import os
from components.monitor import run_monitor_loop, run_monitor
from components.utils import set_config, add_settings_audit
from web.app import app


def setup_systemd_service(directory=None):
    print("Step 1: Setting up systemd service...")
    service_file = '/etc/systemd/system/fim.service'
    project_dir = os.path.dirname(os.path.abspath(__file__))
    main_py_path = os.path.join(project_dir, 'main.py')
    dir_arg = directory if directory else ''
    service_content = f"""
[Unit]
Description=File Integrity Monitor
After=network.target
[Service]
User=root
WorkingDirectory={project_dir}
ExecStart=/usr/bin/python3 {main_py_path} {dir_arg}
Restart=always
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
"""
    with open('fim.service', 'w') as f:
        f.write(service_content)
    subprocess.run(['sudo', 'mv', 'fim.service', service_file])
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
    subprocess.run(['sudo', 'systemctl', 'enable', 'fim'])
    subprocess.run(['sudo', 'systemctl', 'start', 'fim'])
    print("Step 2: Systemd service set up and started.")
    print("Access the web Dashboard at: https://localhost:5000")
    print("Default Creds are admin:admin")
    exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument('directory', type=str, nargs='?', default=None, help="Optional directory to monitor (can add more from Settings)")
    args = parser.parse_args()

    if os.getenv('INVOCATION_ID') is None and args.directory:
        print("Initial run detected. Setting up systemd service...")
        setup_systemd_service(args.directory)

    from components.utils import get_config
    if args.directory:
        path = os.path.abspath(args.directory)
        paths = get_config('monitored_paths') or []
        if path not in paths:
            paths = list(paths) + [path]
            set_config('monitored_paths', paths)
            add_settings_audit(f"CLI added monitored path {path}")
        print(f"Step 1: Monitoring directory: {args.directory}")
    else:
        print("Step 1: No directory from CLI; add paths from Settings in the web UI.")

    set_config('monitoring_active', 1)
    print("Step 2: Starting monitoring thread...")
    monitor_thread = threading.Thread(target=run_monitor_loop, daemon=True)
    monitor_thread.start()
    print("Step 3: Monitoring thread started.")
    print("Step 4: Starting web server...")
    import logging
    log = logging.getLogger('werkzeug')
    log.disabled = True
    app.logger.disabled = True
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False, threaded=True)
