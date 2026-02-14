import argparse
import threading
import subprocess
import os
from components.monitor import run_monitor
from components.web import app

def setup_systemd_service(directory):
    print("Step 1: Setting up systemd service...")
    service_file = '/etc/systemd/system/fim.service'
    project_dir = os.path.dirname(os.path.abspath(__file__))
    main_py_path = os.path.join(project_dir, 'main.py')
   
    service_content = f"""
[Unit]
Description=File Integrity Monitor
After=network.target
[Service]
User=kali
WorkingDirectory={project_dir}
ExecStart=/usr/bin/python3 {main_py_path} {directory}
Restart=always
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
"""
   
    # Write service file (requires sudo)
    with open('fim.service', 'w') as f:
        f.write(service_content)
    subprocess.run(['sudo', 'mv', 'fim.service', service_file])
   
    # Reload, enable, start
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
    subprocess.run(['sudo', 'systemctl', 'enable', 'fim'])
    subprocess.run(['sudo', 'systemctl', 'start', 'fim'])
   
    print("Step 2: Systemd service set up and started.")
    print("The script will now exit; the service runs in the background.")
    exit(0)  # Exit after setup to avoid duplicate run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument('directory', type=str, help="Directory to monitor")
    args = parser.parse_args()
   
    # Detect if running under systemd (INVOCATION_ID is set by systemd)
    if os.getenv('INVOCATION_ID') is None:
        print("Initial run detected. Setting up systemd service...")
        setup_systemd_service(args.directory)
   
    print(f"Step 1: Monitoring directory: {args.directory}")
   
    print("Step 2: Starting monitoring thread...")
    monitor_thread = threading.Thread(target=run_monitor, args=(args.directory,), daemon=True)
    monitor_thread.start()
    print("Step 3: Monitoring thread started.")
   
    print("Step 4: Starting web server...")
   
    # Run Flask quietly
    import logging
    log = logging.getLogger('werkzeug')
    log.disabled = True
    app.logger.disabled = True
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False, threaded=True)
  
