"""All web routes: auth, dashboard, logs, alerts, change password."""
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session

from components.utils import get_logs, get_alerts, load_baseline
from web.auth import login_required, verify_user, change_password_for_user

bp = Blueprint('routes', __name__)

# --- Alert derivation (from original web logic) ---
_ATTR_ALERT_MAP = [
    ('suid', 'Privilege Flag Change', 'critical'),
    ('owner', 'Ownership Change', 'critical'),
    ('mode', 'Permission Change', 'critical'),
    ('group', 'Group Change', 'medium'),
    ('hash', 'File Modified', 'high'),
    ('size', 'File Size Change', 'medium'),
    ('mtime', 'Timestamp Change', 'low'),
]


def _changed_attrs(old_attrs, new_attrs):
    if not old_attrs or not new_attrs:
        return []
    return [k for k in old_attrs if old_attrs.get(k) != new_attrs.get(k)]


def _derive_alert_type_and_severity(alert):
    msg = (alert.get('message') or '')
    details = alert.get('details') or {}
    old_a = details.get('old') or {}
    new_a = details.get('new') or {}
    changed = _changed_attrs(old_a, new_a)
    if 'Deleted' in msg:
        severity = 'high'
        return ('Directory Deleted', severity) if 'directory' in msg else ('File Deleted', severity)
    if 'Renamed' in msg or 'Moved' in msg:
        alert_type = 'Directory Moved / Renamed' if 'directory' in msg else 'File Moved / Renamed'
        severity = 'low'
        if changed:
            severity, alert_type = 'low', 'File Modified'
            for key, atype, sev in _ATTR_ALERT_MAP:
                if key in changed:
                    alert_type, severity = atype, sev
                    break
            if len(changed) > 1 and severity in ('low', 'medium'):
                severity = 'high'
        return alert_type, severity
    if 'New' in msg or 'untracked' in msg:
        severity = 'medium'
        return ('Directory Created', severity) if 'directory' in msg else ('File Created', severity)
    if 'Initial change' in msg or 'Changed' in msg:
        if not changed:
            return 'File Modified', 'medium'
        severity, alert_type = 'low', 'File Modified'
        for key, atype, sev in _ATTR_ALERT_MAP:
            if key in changed:
                alert_type, severity = atype, sev
                break
        if len(changed) > 1 and severity in ('low', 'medium'):
            severity = 'high'
        return alert_type, severity
    if 'Error' in msg or 'Failed' in msg:
        return 'Error', 'high'
    return msg[:40] or 'Alert', 'low'


def _normalize_alert_type(atype):
    if not atype:
        return 'Other'
    if atype == 'Privilege Flag Change':
        return 'SUID Change'
    if atype in ('File Moved / Renamed', 'Directory Moved / Renamed'):
        return 'Move/Rename'
    if atype in ('File Modified', 'File Created', 'File Deleted', 'Permission Change', 'Ownership Change'):
        return atype
    if 'Deleted' in atype or 'Created' in atype:
        return 'File Deleted' if 'Deleted' in atype else 'File Created'
    if 'Permission' in atype or atype == 'Permission Change':
        return 'Permission Change'
    if 'Ownership' in atype or atype == 'Ownership Change':
        return 'Ownership Change'
    if 'Modified' in atype:
        return 'File Modified'
    return atype


def _enrich_alerts(alerts):
    out = []
    for a in alerts:
        alert_type, severity = _derive_alert_type_and_severity(a)
        ts = a.get('timestamp') or ''
        time_short = ts.split()[1][:5] if ts and len(ts) > 10 else ts
        details = a.get('details') or {}
        path = details.get('path') or ''
        if 'old_path' in details and 'new_path' in details:
            path = f"{details['old_path']} → {details['new_path']}"
        out.append({
            **a,
            'alert_type': alert_type,
            'severity': severity,
            'time_short': time_short,
            'path': path,
        })
    return out


def _dashboard_data():
    alerts = get_alerts()
    enriched = _enrich_alerts(alerts)
    now = datetime.now()

    def parse_ts(ts):
        if not ts:
            return None
        try:
            return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return None

    count_critical = count_high = count_medium = count_low = 0
    type_counts = {}
    bucket_counts = {}
    for a in enriched:
        sev = a.get('severity', 'low')
        if sev == 'critical':
            count_critical += 1
        elif sev == 'high':
            count_high += 1
        elif sev == 'medium':
            count_medium += 1
        else:
            count_low += 1
        ts = parse_ts(a.get('timestamp'))
        if ts:
            hour_key = ts.replace(minute=0, second=0, microsecond=0)
            if hour_key not in bucket_counts:
                bucket_counts[hour_key] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            bucket_counts[hour_key][sev] += 1
        atype = a.get('alert_type', 'Other')
        type_norm = _normalize_alert_type(atype)
        type_counts[type_norm] = type_counts.get(type_norm, 0) + 1

    time_labels = []
    series_critical, series_high, series_medium, series_low = [], [], [], []
    for i in range(23, -1, -1):
        hour = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        time_labels.append(hour.strftime('%H:%M'))
        b = bucket_counts.get(hour, {'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
        series_critical.append(b['critical'])
        series_high.append(b['high'])
        series_medium.append(b['medium'])
        series_low.append(b['low'])

    order_types = ['File Modified', 'File Created', 'File Deleted', 'Permission Change', 'Ownership Change', 'SUID Change', 'Move/Rename']
    type_labels, type_values = [], []
    for t in order_types:
        if type_counts.get(t, 0) > 0:
            type_labels.append(t)
            type_values.append(type_counts[t])
    for t, c in sorted(type_counts.items()):
        if t not in order_types:
            type_labels.append(t)
            type_values.append(c)

    baseline = load_baseline()
    files_tracked = len(baseline)
    logs = get_logs()
    last_event = logs[0]['timestamp'] if logs else '—'

    return {
        'count_critical': count_critical,
        'count_high': count_high,
        'count_medium': count_medium,
        'count_low': count_low,
        'status_monitoring': 'ACTIVE',
        'status_baseline': 'LOADED' if files_tracked else 'EMPTY',
        'files_tracked': files_tracked,
        'last_event': last_event,
        'time_labels': time_labels,
        'series_critical': series_critical,
        'series_high': series_high,
        'series_medium': series_medium,
        'series_low': series_low,
        'type_labels': type_labels,
        'type_values': type_values,
    }


# --- Routes ---

@bp.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('routes.dashboard'))
    return redirect(url_for('routes.login'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('routes.dashboard'))
    error = None
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()
        if verify_user(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('routes.dashboard'))
        error = 'Invalid credentials.'
    return render_template('login.html', error=error)


@bp.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('routes.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    data = _dashboard_data()
    return render_template('dashboard.html', **data)


@bp.route('/logs')
@login_required
def show_logs():
    logs = get_logs()
    return render_template('logs.html', logs=logs)


@bp.route('/alerts')
@login_required
def show_alerts():
    alerts = get_alerts()
    alerts = _enrich_alerts(alerts)
    return render_template('alerts.html', alerts=alerts)


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    username = session.get('username') or ''
    error = None
    success = False
    if request.method == 'POST':
        current = (request.form.get('current_password') or '').strip()
        new_pass = (request.form.get('new_password') or '').strip()
        confirm = (request.form.get('confirm_password') or '').strip()
        if new_pass != confirm:
            error = 'New password and confirmation do not match.'
        else:
            ok, msg = change_password_for_user(username, current, new_pass)
            if ok:
                success = True
                error = None
            else:
                error = msg
    return render_template('change_password.html', error=error, success=success)
