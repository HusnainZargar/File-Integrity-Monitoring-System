import pyinotify
import hashlib
import os
import time
import stat
import pwd
import grp
import threading
from .utils import init_db, load_baseline, save_baseline, add_alert

def get_file_attributes(path):
    try:
        st = os.stat(path)
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        mode = oct(st.st_mode & 0o7777)
        suid = bool(st.st_mode & stat.S_ISUID)
        size = st.st_size
        mtime = int(st.st_mtime)
        hash_val = None
        if os.path.isfile(path):
            hash_val = compute_hash(path)
        return {
            "hash": hash_val,
            "owner": owner,
            "group": group,
            "mode": mode,
            "suid": suid,
            "size": size,
            "mtime": mtime
        }
    except Exception as e:
        add_alert(f"Error getting attributes for {path}: {e}")
        return None

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

def compare_attributes(old_attrs, new_attrs):
    changes = [f"{key} from {old_attrs[key]} to {new_attrs[key]}"
               for key in old_attrs if old_attrs[key] != new_attrs[key]]
    return ", ".join(changes) if changes else None

def initial_scan(directory, baseline):
    start_time = time.time()
    paths = []
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            if d.startswith('.'):
                continue
            path = os.path.join(root, d)
            paths.append(path)
        for file in files:
            if file.startswith('.'):
                continue
            path = os.path.join(root, file)
            paths.append(path)
    for path in paths:
        new_attrs = get_file_attributes(path)
        if new_attrs:
            if path not in baseline:
                add_alert(f"Added to baseline: {path}", details={'path': path, 'new': new_attrs})
                baseline[path] = new_attrs
            else:
                old_attrs = baseline[path]
                changes = compare_attributes(old_attrs, new_attrs)
                if changes:
                    add_alert(f"Initial change in {path}: {changes}",
                              details={'path': path, 'old': old_attrs, 'new': new_attrs})
                    baseline[path] = new_attrs
    save_baseline(baseline)
    add_alert(f"Initial scan done in {time.time() - start_time:.2f}s")

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, baseline, wm):
        self.baseline = baseline
        self.wm = wm
        self.pending_moves = {}
        self.pending_timers = {}

    def process_IN_MODIFY(self, event):
        if event.name.startswith('.'):
            return
        self.check_integrity(event.pathname)

    def process_IN_ATTRIB(self, event):
        if event.name.startswith('.'):
            return
        self.check_integrity(event.pathname)

    def process_IN_CREATE(self, event):
        if event.dir:
            self.wm.add_watch(event.pathname, mask, rec=False)
        if event.name.startswith('.'):
            return
        new_attrs = get_file_attributes(event.pathname)
        if new_attrs:
            type_str = "directory" if event.dir else "file"
            add_alert(f"New {type_str}: {event.pathname}", details={'path': event.pathname, 'new': new_attrs})
            self.baseline[event.pathname] = new_attrs
            save_baseline(self.baseline)

    def process_IN_DELETE(self, event):
        if event.name.startswith('.'):
            return
        path = event.pathname
        if path in self.baseline:
            old_attrs = self.baseline.pop(path)
            type_str = "directory" if event.dir else ""
            msg = f"Deleted{ ' ' + type_str if type_str else ''}: {path}"
            add_alert(msg, details={'path': path, 'old': old_attrs})
            save_baseline(self.baseline)

    # ── MOVE HANDLING ─────────────────────────────────────────────────────
    def process_IN_MOVED_FROM(self, event):
        if event.name.startswith('.'):
            return
        cookie = event.cookie
        path = event.pathname
        self.pending_moves[cookie] = (path, event.dir)
        timer = threading.Timer(2.0, self._timeout_moved_from, args=(cookie,))
        timer.start()
        self.pending_timers[cookie] = timer

    def _timeout_moved_from(self, cookie):
        if cookie in self.pending_moves:
            old_path, is_dir = self.pending_moves.pop(cookie)
            if old_path in self.baseline:
                old_attrs = self.baseline.pop(old_path)
                msg = f"Moved outside{ ' directory' if is_dir else ''}: {old_path}"
                add_alert(msg, details={'path': old_path, 'old': old_attrs})
            if is_dir:
                to_remove = [k for k in self.baseline if k.startswith(old_path + '/')]
                for k in to_remove:
                    self.baseline.pop(k)
            save_baseline(self.baseline)
            self.pending_timers.pop(cookie, None)

    def process_IN_MOVED_TO(self, event):
        cookie = event.cookie
        if cookie in self.pending_timers:
            self.pending_timers[cookie].cancel()
            self.pending_timers.pop(cookie, None)
        if event.name.startswith('.'):
            return
        old_tuple = self.pending_moves.pop(cookie, None)
        old_path = old_tuple[0] if old_tuple else None
        is_dir = event.dir
        new_path = event.pathname
        if is_dir:
            self.wm.add_watch(new_path, mask, rec=True, auto_add=True)
        if old_path and old_path in self.baseline:
            # Rename / move inside monitored folder
            old_attrs = self.baseline.pop(old_path)
            new_attrs = get_file_attributes(new_path)
            if new_attrs:
                changes = compare_attributes(old_attrs, new_attrs)
                msg = f"Renamed{ ' directory' if is_dir else ''}: {old_path} → {new_path}"
                if changes:
                    msg += f" and changed ({changes})"
                add_alert(msg, details={'old_path': old_path, 'new_path': new_path,
                                        'old': old_attrs, 'new': new_attrs})
                self.baseline[new_path] = new_attrs
                if is_dir:
                    to_rename = [k for k in self.baseline if k.startswith(old_path + '/')]
                    for old_k in to_rename:
                        new_k = new_path + old_k[len(old_path):]
                        self.baseline[new_k] = self.baseline.pop(old_k)
                save_baseline(self.baseline)
        else:
            self.check_integrity(new_path)
            if is_dir:
                initial_scan(new_path, self.baseline)

    def check_integrity(self, path):
        new_attrs = get_file_attributes(path)
        if new_attrs:
            if path in self.baseline:
                old = self.baseline[path]
                changes = compare_attributes(old, new_attrs)
                if changes:
                    add_alert(f"Changed: {path} ({changes})",
                              details={'path': path, 'old': old, 'new': new_attrs})
                    self.baseline[path] = new_attrs
                    save_baseline(self.baseline)
            else:
                add_alert(f"New/untracked: {path}", details={'path': path, 'new': new_attrs})
                self.baseline[path] = new_attrs
                save_baseline(self.baseline)

def run_monitor(directory):
    init_db()
    baseline = load_baseline()
    initial_scan(directory, baseline)
    global mask
    mask = (pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_CREATE |
            pyinotify.IN_DELETE | pyinotify.IN_MOVE_SELF |
            pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO)
    wm = pyinotify.WatchManager()
    handler = EventHandler(baseline, wm)
    notifier = pyinotify.Notifier(wm, handler)
    wm.add_watch(directory, mask, rec=True, auto_add=True)
    add_alert("Monitoring started")
    notifier.loop()
