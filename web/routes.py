"""All web routes: auth, dashboard, logs, alerts, analysis, settings, account."""
import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, session

from components.utils import (
    get_logs,
    get_alerts,
    load_baseline,
    get_config,
    set_config,
    get_settings_audit,
    add_settings_audit,
    clear_logs,
    get_user,
    get_file_history,
    get_most_changed_files,
    get_hourly_event_counts,
    get_event_type_counts,
)
from components.monitor import (
    get_monitor_state,
    get_scanning_paths,
    stop_notifier,
    add_monitored_path,
    remove_monitored_path,
    create_baseline,
    restart_service,
)
from web.auth import (
    login_required,
    verify_user,
    change_password_for_user,
    change_username_for_user,
    update_login_timestamp,
)

bp = Blueprint('routes', __name__)

PAGE_SIZE = 10   # entries per page for logs and alerts

# ---------------------------------------------------------------------------
# Alert enrichment helpers
# ---------------------------------------------------------------------------

_ATTR_ALERT_MAP = [
    ('suid',  'Privilege Flag Change', 'critical'),
    ('owner', 'Ownership Change',      'critical'),
    ('mode',  'Permission Change',     'critical'),
    ('group', 'Group Change',          'medium'),
    ('hash',  'File Modified',         'high'),
    ('size',  'File Size Change',      'medium'),
    ('mtime', 'Timestamp Change',      'low'),
]


def _changed_attrs(old_attrs, new_attrs):
    if not old_attrs or not new_attrs:
        return []
    return [k for k in old_attrs if old_attrs.get(k) != new_attrs.get(k)]


def _derive_alert_type_and_severity(alert):
    """
    Derive alert type and severity from the event_type field first,
    then fall back to message analysis for legacy rows.
    """
    msg = (alert.get('message') or '')
    details = alert.get('details') or {}
    old_a = details.get('old') or {}
    new_a = details.get('new') or {}
    changed = _changed_attrs(old_a, new_a)

    # Use event_type from DB if available (reliable)
    event_type = alert.get('event_type') or 'info'

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
    if atype in ('File Modified', 'File Created', 'File Deleted',
                 'Permission Change', 'Ownership Change'):
        return atype
    if 'Deleted' in atype or 'Created' in atype:
        return 'File Deleted' if 'Deleted' in atype else 'File Created'
    if 'Permission' in atype:
        return 'Permission Change'
    if 'Ownership' in atype:
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
    alerts_raw, _ = get_alerts()
    enriched = _enrich_alerts(alerts_raw)
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

        atype = _normalize_alert_type(a.get('alert_type', 'Other'))
        type_counts[atype] = type_counts.get(atype, 0) + 1

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

    order_types = ['File Modified', 'File Created', 'File Deleted',
                   'Permission Change', 'Ownership Change', 'SUID Change', 'Move/Rename']
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
    logs_raw, _ = get_logs(limit=1)
    last_event = logs_raw[0]['timestamp'] if logs_raw else '—'

    state = get_monitor_state()
    status_monitoring = (
        'ACTIVE' if (state.get('monitoring_active') and state.get('notifier_running'))
        else 'PAUSED'
    )

    return {
        'count_critical': count_critical,
        'count_high': count_high,
        'count_medium': count_medium,
        'count_low': count_low,
        'status_monitoring': status_monitoring,
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


# ---------------------------------------------------------------------------
# Routes — auth
# ---------------------------------------------------------------------------

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
            update_login_timestamp(username)
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


# ---------------------------------------------------------------------------
# Routes — main views
# ---------------------------------------------------------------------------

@bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', **_dashboard_data())


@bp.route('/logs')
@login_required
def show_logs():
    page = max(1, int(request.args.get('page', 1)))
    search = (request.args.get('search') or '').strip()
    offset = (page - 1) * PAGE_SIZE
    logs, total = get_logs(limit=PAGE_SIZE, offset=offset, search=search or None)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return render_template('logs.html',
                           logs=logs,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           search=search)


@bp.route('/alerts')
@login_required
def show_alerts():
    page = max(1, int(request.args.get('page', 1)))
    search = (request.args.get('search') or '').strip()
    offset = (page - 1) * PAGE_SIZE
    alerts_raw, total = get_alerts(limit=PAGE_SIZE, offset=offset, search=search or None)
    alerts = _enrich_alerts(alerts_raw)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return render_template('alerts.html',
                           alerts=alerts,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           search=search)


# ---------------------------------------------------------------------------
# Routes — analysis
# ---------------------------------------------------------------------------

FILE_ANALYSIS_PAGE_SIZE = 5

@bp.route('/analysis/file')
@login_required
def file_analysis():
    baseline = load_baseline()
    selected_path = (request.args.get('path') or '').strip()
    search = (request.args.get('search') or '').strip()
    page = max(1, int(request.args.get('page', 1)))

    # Filter + sort paths
    all_paths = sorted(baseline.keys())
    if search:
        filtered = [p for p in all_paths if search.lower() in p.lower()]
    else:
        filtered = all_paths

    total = len(filtered)
    total_pages = max(1, (total + FILE_ANALYSIS_PAGE_SIZE - 1) // FILE_ANALYSIS_PAGE_SIZE)
    page = min(page, total_pages)
    offset = (page - 1) * FILE_ANALYSIS_PAGE_SIZE
    page_paths = filtered[offset: offset + FILE_ANALYSIS_PAGE_SIZE]

    file_attrs = None
    history = []

    if selected_path and selected_path in baseline:
        file_attrs = baseline[selected_path]
        history = get_file_history(selected_path)
    elif selected_path:
        # Removed from baseline but history may still exist
        history = get_file_history(selected_path)

    return render_template('file_analysis.html',
                           page_paths=page_paths,
                           selected_path=selected_path,
                           file_attrs=file_attrs,
                           history=history,
                           search=search,
                           page=page,
                           total_pages=total_pages,
                           total=total)


@bp.route('/analysis/statistics')
@login_required
def statistics():
    baseline = load_baseline()
    files_tracked = len(baseline)

    most_changed = get_most_changed_files(limit=10)
    hourly_counts = get_hourly_event_counts()
    event_type_counts = get_event_type_counts()

    # Directory breakdown: group baseline files by parent dir
    dir_counts = {}
    for path in baseline:
        parent = os.path.dirname(path)
        dir_counts[parent] = dir_counts.get(parent, 0) + 1
    top_dirs = sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Baseline drift: files that appear in any alert
    alerts_raw, _ = get_alerts()
    alerted_paths = set()
    for a in alerts_raw:
        details = a.get('details') or {}
        p = details.get('path') or details.get('new_path') or ''
        if p:
            alerted_paths.add(p)
    drift_count = len(alerted_paths)
    drift_pct = round((drift_count / files_tracked * 100) if files_tracked else 0, 1)

    # SUID change count
    suid_count = event_type_counts.get('suid_change', 0)

    # Hourly labels/values for chart
    hourly_labels = [f"{h}:00" for h in range(24)]
    hourly_values = [hourly_counts.get(str(i).zfill(2), 0) for i in range(24)]

    # Event type chart data
    et_labels = list(event_type_counts.keys())
    et_values = list(event_type_counts.values())

    # Most changed files chart data
    mc_labels = [os.path.basename(f['path']) or f['path'] for f in most_changed]
    mc_full_paths = [f['path'] for f in most_changed]
    mc_values = [f['count'] for f in most_changed]

    # Top dirs chart data
    td_labels = [os.path.basename(d[0]) or d[0] for d in top_dirs]
    td_values = [d[1] for d in top_dirs]

    return render_template('statistics.html',
                           files_tracked=files_tracked,
                           drift_count=drift_count,
                           drift_pct=drift_pct,
                           suid_count=suid_count,
                           hourly_labels=hourly_labels,
                           hourly_values=hourly_values,
                           et_labels=et_labels,
                           et_values=et_values,
                           mc_labels=mc_labels,
                           mc_full_paths=mc_full_paths,
                           mc_values=mc_values,
                           td_labels=td_labels,
                           td_values=td_values,
                           most_changed=most_changed)


# ---------------------------------------------------------------------------
# Routes — settings
# ---------------------------------------------------------------------------

@bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    username = session.get('username') or ''
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'monitoring_status':
            val = 1 if request.form.get('status') == 'active' else 0
            set_config('monitoring_active', val)
            if val == 0:
                stop_notifier()
            add_settings_audit('Monitoring set to ' + ('ACTIVE' if val else 'PAUSED'))
        elif action == 'add_path':
            path = (request.form.get('path') or '').strip()
            ok, msg = add_monitored_path(path, who=username)
            if not ok:
                return render_template('settings.html',
                                       config=_settings_config(),
                                       audit=get_settings_audit(),
                                       path_error=msg)
        elif action == 'remove_path':
            path = (request.form.get('path') or '').strip()
            remove_monitored_path(path, who=username)
        elif action == 'recursive':
            val = 1 if request.form.get('recursive') == 'on' else 0
            set_config('recursive', val)
            add_settings_audit('Recursive monitoring ' + ('ON' if val else 'OFF'))
        elif action == 'ignore_hidden':
            val = 1 if request.form.get('ignore_hidden') == 'on' else 0
            set_config('ignore_hidden', val)
            add_settings_audit('Ignore hidden files ' + ('ON' if val else 'OFF'))
        elif action == 'auto_baseline':
            val = 1 if request.form.get('auto_baseline') == 'on' else 0
            set_config('auto_update_baseline', val)
            add_settings_audit('Auto-update baseline ' + ('ON' if val else 'OFF'))
        elif action == 'add_exclusion':
            ex = (request.form.get('exclusion') or '').strip()
            if ex:
                excluded = list(get_config('excluded_paths') or [])
                if ex not in excluded:
                    excluded.append(ex)
                    set_config('excluded_paths', excluded)
                    add_settings_audit(f'Added exclusion {ex}')
        elif action == 'remove_exclusion':
            ex = (request.form.get('path') or '').strip()
            excluded = [p for p in (get_config('excluded_paths') or []) if p != ex]
            set_config('excluded_paths', excluded)
            add_settings_audit(f'Removed exclusion {ex}')
        elif action == 'clear_baseline_rescan':
            clear_logs()
            create_baseline(who=username)
        elif action == 'restart':
            restart_service(who=username)
        return redirect(url_for('routes.settings'))
    return render_template('settings.html',
                           config=_settings_config(),
                           audit=get_settings_audit(),
                           path_error=None)


def _settings_config():
    state = get_monitor_state()
    paths = get_config('monitored_paths') or []
    scanning = get_scanning_paths()

    def status(p):
        if p in scanning:
            return 'scanning'
        if os.path.isfile(p) or os.path.isdir(p):
            return 'active'
        return 'failed'

    path_status = [(p, status(p)) for p in paths]
    return {
        'monitoring_active': get_config('monitoring_active'),
        'notifier_running': state.get('notifier_running', False),
        'monitored_paths': paths,
        'path_status': path_status,
        'recursive': get_config('recursive'),
        'ignore_hidden': get_config('ignore_hidden'),
        'auto_update_baseline': get_config('auto_update_baseline'),
        'excluded_paths': get_config('excluded_paths') or [],
    }


# ---------------------------------------------------------------------------
# Routes — account
# ---------------------------------------------------------------------------

@bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    username = session.get('username') or ''
    user = get_user(username)
    last_login = (user or {}).get('last_login') or '—'
    pw_error = request.args.get('pw_error')
    pw_success = request.args.get('pw_success') == '1'
    un_error = None
    un_success = False

    if request.method == 'POST':
        sub = request.form.get('account_submit')
        if sub == 'password':
            current = (request.form.get('current_password') or '').strip()
            new_pass = (request.form.get('new_password') or '').strip()
            confirm = (request.form.get('confirm_password') or '').strip()
            if new_pass != confirm:
                pw_error = 'New password and confirmation do not match.'
            else:
                ok, msg = change_password_for_user(username, current, new_pass)
                if ok:
                    pw_success = True
                else:
                    pw_error = msg
        elif sub == 'username':
            password = (request.form.get('password_for_username') or '').strip()
            new_username = (request.form.get('new_username') or '').strip()
            ok, msg = change_username_for_user(username, new_username, password)
            if ok:
                session['username'] = new_username
                un_success = True
                username = new_username
                user = get_user(new_username)
                last_login = (user or {}).get('last_login') or '—'
            else:
                un_error = msg

    return render_template('account.html',
                           username=username,
                           last_login=last_login,
                           pw_error=pw_error,
                           pw_success=pw_success,
                           un_error=un_error,
                           un_success=un_success)


@bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'GET':
        return redirect(url_for('routes.account'))
    username = session.get('username') or ''
    current = (request.form.get('current_password') or '').strip()
    new_pass = (request.form.get('new_password') or '').strip()
    confirm = (request.form.get('confirm_password') or '').strip()
    if new_pass != confirm:
        return redirect(url_for('routes.account',
                                pw_error='New password and confirmation do not match.'))
    ok, msg = change_password_for_user(username, current, new_pass)
    return redirect(url_for('routes.account',
                            pw_success='1' if ok else None,
                            pw_error=msg if not ok else None))
