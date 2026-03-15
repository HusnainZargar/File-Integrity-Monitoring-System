import os
import sqlite3
import time
import json

_components_dir = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(_components_dir, 'baseline.db')


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS baselines (
        path TEXT PRIMARY KEY,
        attributes TEXT
    )''')
    # logs table: event_type column added for reliable filtering
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        message TEXT,
        details TEXT,
        event_type TEXT DEFAULT 'info'
    )''')
    # file_history: every attribute snapshot for every file, never overwritten
    c.execute('''CREATE TABLE IF NOT EXISTS file_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        path TEXT,
        event TEXT,
        attributes TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        last_login TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        message TEXT
    )''')

    # Migrate existing logs table if columns missing
    c.execute("PRAGMA table_info(logs)")
    log_cols = [col[1] for col in c.fetchall()]
    if 'details' not in log_cols:
        c.execute("ALTER TABLE logs ADD COLUMN details TEXT")
    if 'event_type' not in log_cols:
        c.execute("ALTER TABLE logs ADD COLUMN event_type TEXT DEFAULT 'info'")

    # Migrate users table if last_login missing
    c.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in c.fetchall()]
    if 'last_login' not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def get_user(username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("SELECT username, password_hash, last_login FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {'username': row[0], 'password_hash': row[1], 'last_login': row[2]}
    except sqlite3.OperationalError:
        conn.close()
        return None


def update_user_password(username, password_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))
    conn.commit()
    conn.close()


def create_user(username, password_hash):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    finally:
        conn.close()


def user_count():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    n = c.fetchone()[0]
    conn.close()
    return n


def update_last_login(username):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET last_login = ? WHERE username = ?", (ts, username))
    conn.commit()
    conn.close()


def update_username(old_username, new_username):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, old_username))
        if c.rowcount == 0:
            return False
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = {
    'monitoring_active': 1,
    'monitored_paths': [],
    'recursive': 1,
    'ignore_hidden': 1,
    'auto_update_baseline': 0,
    'excluded_paths': [],
}


def get_config(key):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT value FROM config WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    if row is None:
        return _DEFAULT_CONFIG.get(key)
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return row[0]


def set_config(key, value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    v = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
    c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, v))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Settings audit
# ---------------------------------------------------------------------------

def add_settings_audit(message):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO settings_audit (timestamp, message) VALUES (?, ?)", (ts, message))
    conn.commit()
    conn.close()


def get_settings_audit(limit=100):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, message FROM settings_audit ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'timestamp': r[0], 'message': r[1]} for r in rows]


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT path, attributes FROM baselines")
    baseline = {row[0]: json.loads(row[1]) for row in c.fetchall()}
    conn.close()
    return baseline


def save_baseline(baseline):
    """Persist entire baseline dict to DB."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for path, attrs in baseline.items():
        attrs_json = json.dumps(attrs)
        c.execute("INSERT OR REPLACE INTO baselines (path, attributes) VALUES (?, ?)",
                  (path, attrs_json))
    conn.commit()
    conn.close()


def update_baseline_entry(path, attrs):
    """Update or insert a single baseline entry."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO baselines (path, attributes) VALUES (?, ?)",
              (path, json.dumps(attrs)))
    conn.commit()
    conn.close()


def remove_baseline_under_path(path_prefix):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    prefix = path_prefix.rstrip('/') + '/'
    c.execute("DELETE FROM baselines WHERE path = ? OR path LIKE ?", (path_prefix, prefix + '%'))
    conn.commit()
    conn.close()


def clear_baseline():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM baselines")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# File history — immutable append-only log of every attribute snapshot
# ---------------------------------------------------------------------------

def add_file_history(path, event, attributes):
    """
    Append a snapshot of file attributes to the history log.
    event: 'baseline', 'modified', 'created', 'deleted', 'moved', 'permission_change',
            'ownership_change', 'suid_change', 'timestamp_change', 'size_change'
    attributes: dict of file attributes at the time of the event
    """
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO file_history (timestamp, path, event, attributes) VALUES (?, ?, ?, ?)",
        (ts, path, event, json.dumps(attributes) if attributes else None)
    )
    conn.commit()
    conn.close()


def get_file_history(path, limit=200):
    """Return all history entries for a specific path, newest first."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, path, event, attributes FROM file_history WHERE path = ? ORDER BY id DESC LIMIT ?",
        (path, limit)
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            'timestamp': r[0],
            'path': r[1],
            'event': r[2],
            'attributes': json.loads(r[3]) if r[3] else None
        }
        for r in rows
    ]


def get_all_file_history(limit=1000):
    """Return most recent history entries across all files."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, path, event, attributes FROM file_history ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            'timestamp': r[0],
            'path': r[1],
            'event': r[2],
            'attributes': json.loads(r[3]) if r[3] else None
        }
        for r in rows
    ]


def get_most_changed_files(limit=10):
    """Return top N files by number of change events in file_history."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT path, COUNT(*) as cnt FROM file_history
        WHERE event != 'baseline'
        GROUP BY path ORDER BY cnt DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'path': r[0], 'count': r[1]} for r in rows]


def get_hourly_event_counts():
    """Return event counts grouped by hour (last 24h) for statistics heatmap."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT strftime('%H', timestamp) as hr, COUNT(*) as cnt
        FROM file_history
        WHERE event != 'baseline'
          AND timestamp >= datetime('now', '-24 hours')
        GROUP BY hr ORDER BY hr
    """)
    rows = c.fetchall()
    conn.close()
    result = {str(i).zfill(2): 0 for i in range(24)}
    for r in rows:
        result[r[0]] = r[1]
    return result


def get_event_type_counts():
    """Return counts per event type in file_history (excluding baseline)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT event, COUNT(*) FROM file_history
        WHERE event != 'baseline'
        GROUP BY event ORDER BY COUNT(*) DESC
    """)
    rows = c.fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}


# ---------------------------------------------------------------------------
# Logs / Alerts
# ---------------------------------------------------------------------------

def add_alert(message, details=None, event_type='info'):
    """
    Log an event.
    event_type: 'info' for operational messages, 'alert' for integrity violations.
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    details_json = json.dumps(details) if details else None
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (timestamp, message, details, event_type) VALUES (?, ?, ?, ?)",
        (timestamp, message, details_json, event_type)
    )
    conn.commit()
    conn.close()


def get_logs(limit=None, offset=0, search=None):
    """Return log entries (all types), newest first, with optional search and pagination."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    params = []
    where = ""
    if search:
        where = "WHERE message LIKE ?"
        params.append(f'%{search}%')

    # Count
    c.execute(f"SELECT COUNT(*) FROM logs {where}", params)
    total = c.fetchone()[0]

    query = f"SELECT timestamp, message, details, event_type FROM logs {where} ORDER BY id DESC"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params_q = params + [limit, offset]
    else:
        params_q = params
    c.execute(query, params_q)
    logs = [
        {
            'timestamp': row[0],
            'message': row[1],
            'details': json.loads(row[2]) if row[2] else None,
            'event_type': row[3] or 'info',
        }
        for row in c.fetchall()
    ]
    conn.close()
    return logs, total


def get_alerts(limit=None, offset=0, search=None):
    """Return only integrity alert entries (event_type='alert'), newest first."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    params = ['alert']
    where_extra = ""
    if search:
        where_extra = "AND message LIKE ?"
        params.append(f'%{search}%')

    c.execute(f"SELECT COUNT(*) FROM logs WHERE event_type = ? {where_extra}", params)
    total = c.fetchone()[0]

    query = f"""
        SELECT timestamp, message, details, event_type FROM logs
        WHERE event_type = ? {where_extra}
        ORDER BY id DESC
    """
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params_q = params + [limit, offset]
    else:
        params_q = params
    c.execute(query, params_q)
    alerts = [
        {
            'timestamp': row[0],
            'message': row[1],
            'details': json.loads(row[2]) if row[2] else None,
            'event_type': row[3],
        }
        for row in c.fetchall()
    ]
    conn.close()
    return alerts, total


def clear_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()


def clear_settings_audit():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM settings_audit")
    conn.commit()
    conn.close()


def clear_all_except_account():
    """Clear logs, file_history, settings_audit, baselines, and config. Does not touch users."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("DELETE FROM logs")
        c.execute("DELETE FROM file_history")
        c.execute("DELETE FROM settings_audit")
        c.execute("DELETE FROM baselines")
        c.execute("DELETE FROM config")
        conn.commit()
        return True
    except sqlite3.OperationalError as e:
        conn.rollback()
        add_alert(f"clear_all_except_account failed: {e}", event_type='info')
        return False
    finally:
        conn.close()
