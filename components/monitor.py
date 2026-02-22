import pyinotify
import hashlib
import os
import time
import stat
import pwd
import grp
import threading
from .utils import (
    init_db,
    load_baseline,
    save_baseline,
    add_alert,
    get_config,
    set_config,
    remove_baseline_under_path,
    clear_baseline,
    clear_all_except_account,
    add_settings_audit,
)

# Module-level state for monitor thread and web control
_lock = threading.RLock()
_wm = None
_notifier = None
_handler = None
_baseline = None
_watched_paths = {}  # path -> watch descriptor
_mask = None
_scanning_paths = set()  # paths currently being initial_scan'd (for UI "Scanning" status)


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


def _is_excluded(pathname):
    """True if pathname should be excluded per config."""
    excluded = get_config('excluded_paths') or []
    pathname = os.path.normpath(pathname)
    for prefix in excluded:
        if not prefix:
            continue
        p = os.path.normpath(prefix).rstrip(os.sep)
        if pathname == p or pathname.startswith(p + os.sep):
            return True
    return False


def _should_save_baseline():
    return get_config('auto_update_baseline')


def _should_ignore_hidden():
    return get_config('ignore_hidden')


def _recursive():
    return get_config('recursive')


def initial_scan(path_or_dir, baseline, save_after=None):
    """Scan a file or directory and update baseline. save_after: None=use config, True=always save, False=never save."""
    start_time = time.time()
    if os.path.isfile(path_or_dir):
        new_attrs = get_file_attributes(path_or_dir)
        if new_attrs:
            if path_or_dir not in baseline:
                add_alert(f"Added to baseline: {path_or_dir}", details={'path': path_or_dir, 'new': new_attrs})
                baseline[path_or_dir] = new_attrs
            else:
                old_attrs = baseline[path_or_dir]
                changes = compare_attributes(old_attrs, new_attrs)
                if changes:
                    add_alert(f"Initial change in {path_or_dir}: {changes}",
                              details={'path': path_or_dir, 'old': old_attrs, 'new': new_attrs})
                    baseline[path_or_dir] = new_attrs
        do_save = save_after if save_after is not None else _should_save_baseline()
        if do_save:
            save_baseline(baseline)
        add_alert(f"Initial scan done in {time.time() - start_time:.2f}s")
        return
    ignore_hidden = _should_ignore_hidden()
    paths = []
    for root, dirs, files in os.walk(path_or_dir):
        if ignore_hidden:
            dirs[:] = [d for d in dirs if not d.startswith('.')]
        for d in dirs:
            path = os.path.join(root, d)
            if _is_excluded(path):
                continue
            paths.append(path)
        for file in files:
            if ignore_hidden and file.startswith('.'):
                continue
            path = os.path.join(root, file)
            if _is_excluded(path):
                continue
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
    do_save = save_after if save_after is not None else _should_save_baseline()
    if do_save:
        save_baseline(baseline)
    add_alert(f"Initial scan done in {time.time() - start_time:.2f}s")


def get_scanning_paths():
    """Return set of paths currently being scanned (for UI status)."""
    with _lock:
        return set(_scanning_paths)


def add_watches_filtered(wm, base_path, mask):
    added = {}
    def add_rec(p):
        if _is_excluded(p) or (_should_ignore_hidden() and os.path.basename(p).startswith('.')):
            return
        try:
            wd_dict = wm.add_watch(p, mask)
            if isinstance(wd_dict, int) and wd_dict > 0:
                added[p] = wd_dict
            elif isinstance(wd_dict, dict):
                for k, v in wd_dict.items():
                    if v > 0:
                        added[k] = v
        except Exception as e:
            add_alert(f"Failed to add watch to {p}: {e}")
            return
        try:
            for sub in os.listdir(p):
                subp = os.path.join(p, sub)
                if os.path.isdir(subp):
                    add_rec(subp)
        except Exception as e:
            add_alert(f"Error listing dir {p}: {e}")
    if not os.path.exists(base_path):
        return {}
    if os.path.isfile(base_path):
        try:
            wd_dict = wm.add_watch(base_path, mask)
            if isinstance(wd_dict, int) and wd_dict > 0:
                added[base_path] = wd_dict
            elif isinstance(wd_dict, dict):
                for k, v in wd_dict.items():
                    if v > 0:
                        added[k] = v
        except Exception as e:
            add_alert(f"Failed to watch file {base_path}: {e}")
    elif os.path.isdir(base_path):
        add_rec(base_path)
    return added


def remove_watches_under(wm, base_path):
    with _lock:
        base_path = os.path.normpath(base_path)
        to_del = [k for k in list(_watched_paths) if os.path.normpath(k) == base_path or os.path.normpath(k).startswith(base_path + os.sep)]
        if to_del:
            wds = [_watched_paths[k] for k in to_del]
            try:
                wm.rm_watch(wds)
            except Exception as e:
                add_alert(f"Error removing watches: {e}")
            for k in to_del:
                del _watched_paths[k]


class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, baseline, wm):
        self.baseline = baseline
        self.wm = wm
        self.pending_moves = {}
        self.pending_timers = {}

    def _skip(self, event):
        if _is_excluded(event.pathname):
            return True
        if not _should_ignore_hidden():
            return False
        if event.name.startswith('.'):
            return True
        # Check if any ancestor directory is hidden
        dir_path = os.path.dirname(event.pathname)
        while dir_path and dir_path != '/':
            if os.path.basename(dir_path).startswith('.'):
                return True
            dir_path = os.path.dirname(dir_path)
        return False

    def process_IN_MODIFY(self, event):
        if self._skip(event):
            return
        self.check_integrity(event.pathname)

    def process_IN_ATTRIB(self, event):
        if self._skip(event):
            return
        self.check_integrity(event.pathname)

    def process_IN_CREATE(self, event):
        if self._skip(event):
            return
        if event.dir:
            added = add_watches_filtered(self.wm, event.pathname, _mask)
            with _lock:
                _watched_paths.update(added)
        new_attrs = get_file_attributes(event.pathname)
        if new_attrs:
            type_str = "directory" if event.dir else "file"
            add_alert(f"New {type_str}: {event.pathname}", details={'path': event.pathname, 'new': new_attrs})
            self.baseline[event.pathname] = new_attrs
            if _should_save_baseline():
                save_baseline(self.baseline)

    def process_IN_DELETE(self, event):
        if self._skip(event):
            return
        path = event.pathname
        if event.dir:
            remove_watches_under(self.wm, path)
        if path in self.baseline:
            old_attrs = self.baseline.pop(path)
            type_str = "directory" if event.dir else ""
            msg = f"Deleted{ ' ' + type_str if type_str else ''}: {path}"
            add_alert(msg, details={'path': path, 'old': old_attrs})
            if _should_save_baseline():
                save_baseline(self.baseline)

    def process_IN_MOVED_FROM(self, event):
        if self._skip(event):
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
                remove_watches_under(self.wm, old_path)
            if _should_save_baseline():
                save_baseline(self.baseline)
            self.pending_timers.pop(cookie, None)

    def process_IN_MOVED_TO(self, event):
        cookie = event.cookie
        if cookie in self.pending_timers:
            self.pending_timers[cookie].cancel()
            self.pending_timers.pop(cookie, None)
        if self._skip(event):
            return
        old_tuple = self.pending_moves.pop(cookie, None)
        old_path = old_tuple[0] if old_tuple else None
        is_dir = event.dir
        new_path = event.pathname
        if is_dir:
            added = add_watches_filtered(self.wm, new_path, _mask)
            with _lock:
                _watched_paths.update(added)
        if old_path and old_path in self.baseline:
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
                    to_rename = [k for k in list(self.baseline) if k.startswith(old_path + '/')]
                    for old_k in to_rename:
                        new_k = new_path + old_k[len(old_path):]
                        self.baseline[new_k] = self.baseline.pop(old_k)
                    with _lock:
                        to_rename_w = [k for k in list(_watched_paths) if k.startswith(old_path + '/')]
                        for old_k in to_rename_w:
                            new_k = new_path + old_k[len(old_path):]
                            _watched_paths[new_k] = _watched_paths.pop(old_k)
                if _should_save_baseline():
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
                    if _should_save_baseline():
                        save_baseline(self.baseline)
            else:
                add_alert(f"New/untracked: {path}", details={'path': path, 'new': new_attrs})
                self.baseline[path] = new_attrs
                if _should_save_baseline():
                    save_baseline(self.baseline)


# --- Monitor control (for web and main) ---

def get_monitor_state():
    """Return dict: active (bool), notifier_running (bool)."""
    with _lock:
        active = bool(get_config('monitoring_active'))
        running = _notifier is not None
        return {'monitoring_active': active, 'notifier_running': running}


def stop_notifier():
    """Stop the notifier loop (pause). Call from web when setting monitoring_active=0."""
    with _lock:
        if _notifier is not None:
            _notifier.stop()


def _do_scan_then_clear(path):
    """Background: run initial_scan for path then remove from _scanning_paths."""
    try:
        with _lock:
            bl = _baseline
        if bl is not None:
            initial_scan(path, bl, save_after=True)
    finally:
        with _lock:
            _scanning_paths.discard(path)


def add_monitored_path(path, who='admin'):
    """Add a file or directory to monitoring (and config). Validates path. Returns (True, None) or (False, error_msg)."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return False, 'Path does not exist.'
    if not os.path.isfile(path) and not os.path.isdir(path):
        return False, 'Path must be a file or directory.'
    if not os.access(path, os.R_OK):
        return False, 'Path is not readable.'
    paths = get_config('monitored_paths') or []
    if path in paths:
        return False, 'Path is already monitored.'
    with _lock:
        paths = list(paths) + [path]
        set_config('monitored_paths', paths)
        _scanning_paths.add(path)
        if _wm is not None and _baseline is not None:
            try:
                added = add_watches_filtered(_wm, path, _mask)
                _watched_paths.update(added)
            except Exception as e:
                _scanning_paths.discard(path)
                add_alert(f"Failed to watch {path}: {e}")
                return False, str(e)
            t = threading.Thread(target=_do_scan_then_clear, args=(path,), daemon=True)
            t.start()
        else:
            _scanning_paths.discard(path)
        add_settings_audit(f"User {who} added monitored path {path}")
    return True, None


def remove_monitored_path(path, who='admin'):
    """Remove path from monitoring, config, and baseline."""
    path = os.path.normpath(os.path.abspath(path))
    paths = get_config('monitored_paths') or []
    if path not in paths:
        return False, 'Path is not in monitored list.'
    with _lock:
        paths = [p for p in paths if os.path.normpath(p) != path]
        set_config('monitored_paths', paths)
        if _wm is not None:
            remove_watches_under(_wm, path)
        if _baseline is not None:
            remove_baseline_under_path(path)
            # Also remove from in-memory baseline
            to_del = [k for k in list(_baseline) if k == path or k.startswith(path + '/')]
            for k in to_del:
                del _baseline[k]
        add_settings_audit(f"User {who} removed monitored path {path}")
    return True, None


def run_monitor_loop():
    """Main loop: run notifier when active, sleep when paused. Reads config for paths."""
    global _wm, _notifier, _handler, _baseline, _mask
    init_db()
    _mask = (pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB | pyinotify.IN_CREATE |
             pyinotify.IN_DELETE | pyinotify.IN_MOVE_SELF |
             pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO)
    while True:
        while not get_config('monitoring_active'):
            with _lock:
                if _notifier is not None:
                    try:
                        _notifier.stop()
                    except Exception:
                        pass
                    _notifier = None
                    _wm = None
                    _handler = None
                    _baseline = None
                    _watched_paths = {}
            time.sleep(1)
        paths = get_config('monitored_paths') or []
        if not paths:
            time.sleep(2)
            continue
        with _lock:
            _baseline = load_baseline()
            _wm = pyinotify.WatchManager()
            _handler = EventHandler(_baseline, _wm)
            _notifier = pyinotify.Notifier(_wm, _handler)
            _watched_paths = {}
            for p in paths:
                try:
                    added = add_watches_filtered(_wm, p, _mask)
                    _watched_paths.update(added)
                except Exception as e:
                    add_alert(f"Failed to watch {p}: {e}")
            for p in paths:
                _scanning_paths.add(p)
        for p in paths:
            if os.path.isfile(p) or os.path.isdir(p):
                initial_scan(p, _baseline, save_after=True)
        with _lock:
            for p in paths:
                _scanning_paths.discard(p)
        add_alert("Monitoring started")
        try:
            _notifier.loop()
        except Exception as e:
            add_alert(f"Notifier error: {e}")
        with _lock:
            _notifier = None
            _wm = None
            _handler = None
            _watched_paths = {}


def run_monitor(directory):
    """Legacy: set single directory in config and run the loop (for CLI compatibility)."""
    paths = get_config('monitored_paths') or []
    if directory and directory not in paths:
        paths = list(paths) + [os.path.abspath(directory)]
        set_config('monitored_paths', paths)
        add_settings_audit(f"CLI added monitored path {directory}")
    if get_config('monitoring_active') is None:
        set_config('monitoring_active', 1)
    run_monitor_loop()


def create_baseline(who='admin'):
    """Clear baseline and rebuild from all monitored paths. If monitor is running, sync in-memory baseline."""
    paths = get_config('monitored_paths') or []
    clear_baseline()
    baseline = load_baseline()  # now empty {}
    for p in paths:
        if os.path.isfile(p) or os.path.isdir(p):
            initial_scan(p, baseline, save_after=False)
    save_baseline(baseline)
    with _lock:
        if _baseline is not None:
            _baseline.clear()
            _baseline.update(baseline)
    add_settings_audit(f"User {who} created baseline from {len(paths)} path(s)")


def reset_baseline(who='admin'):
    """Same as create_baseline (explicit reset intent)."""
    create_baseline(who=who)
    add_settings_audit(f"User {who} reset baseline")


def restart_service(who='admin'):
    """Clear everything except account: logs, settings audit, baselines, monitored paths; stop notifier."""
    stop_notifier()
    init_db()
    clear_all_except_account()
    set_config('monitored_paths', [])
    set_config('monitoring_active', 0)
    add_settings_audit(f"User {who} restarted service (database cleared except account)")
