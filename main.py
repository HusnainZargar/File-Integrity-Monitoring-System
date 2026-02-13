import argparse
import threading
from components.monitor import run_monitor
from components.web import app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple File Integrity Monitor")
    parser.add_argument('directory', type=str, help="Directory to monitor")
    args = parser.parse_args()
    
    print(f"Monitoring: {args.directory}")
    
    # Start monitoring in a thread
    monitor_thread = threading.Thread(target=run_monitor, args=(args.directory,), daemon=True)
    monitor_thread.start()
    
    print("Monitoring started. Access logs at http://localhost:5002/logs")
    
    # Run Flask web server
    app.run(host='127.0.0.1', port=5002, debug=False)
