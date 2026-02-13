import pyinotify
import hashlib
import os
import time
from .utils import init_db, load_baseline, save_baseline, add_alert

def compute_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        add_alert(f"Error hashing {file_path}: {e}")
        return None

def initial_scan(directory, baseline):
    start_time = time.time()
    paths = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('.'): continue  # Skip hidden
            path = os.path.join(root, file)
            if os.path.isfile(path):
                paths.append(path)
    
    for path in paths:  # Simple loop; no parallel for minimal
        new_hash = compute_hash(path)
        if new_hash and (path not in baseline or baseline[path] != new_hash):
            add_alert(f"Initial change: {path}")
            baseline[path] = new_hash
    
    save_baseline(baseline)
    add_alert(f"Initial scan done in {time.time() - start_time:.2f}s")

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, baseline, wm):
        self.baseline = baseline
        self.wm = wm

    def process_IN_MODIFY(self, event):
        if event.dir or event.name.startswith('.'): return
        self.check_integrity(event.pathname)

    def process_IN_CREATE(self, event):
        if event.dir:
            self.wm.add_watch(event.pathname, mask, rec=False)
        elif not event.name.startswith('.'):
            new_hash = compute_hash(event.pathname)
            if new_hash:
                add_alert(f"New file: {event.pathname}")
                self.baseline[event.pathname] = new_hash
                save_baseline(self.baseline)

    def process_IN_DELETE(self, event):
        if event.pathname in self.baseline:
            del self.baseline[event.pathname]
            add_alert(f"Deleted: {event.pathname}")
            save_baseline(self.baseline)

    def process_IN_MOVE_SELF(self, event):
        add_alert(f"Moved: {event.pathname}")

    def check_integrity(self, path):
        current_hash = compute_hash(path)
        if current_hash and path in self.baseline:
            if current_hash != self.baseline[path]:
                add_alert(f"Changed: {path}")
                self.baseline[path] = current_hash
                save_baseline(self.baseline)
        elif current_hash:
            add_alert(f"New/untracked: {path}")
            self.baseline[path] = current_hash
            save_baseline(self.baseline)

def run_monitor(directory):
    init_db()
    baseline = load_baseline()
    initial_scan(directory, baseline)
    
    global mask
    mask = pyinotify.IN_MODIFY | pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MOVE_SELF
    
    wm = pyinotify.WatchManager()
    handler = EventHandler(baseline, wm)
    notifier = pyinotify.Notifier(wm, handler)
    
    wm.add_watch(directory, mask, rec=True, auto_add=True)
    
    add_alert("Monitoring started")
    notifier.loop()
