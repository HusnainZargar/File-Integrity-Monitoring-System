from datetime import datetime
from flask import Flask, render_template_string
from .utils import get_logs, get_alerts
app = Flask(__name__)
# Map attribute key -> (alert_type, severity)
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
    path = details.get('path') or ''
    old_a = details.get('old') or {}
    new_a = details.get('new') or {}
    changed = _changed_attrs(old_a, new_a)
    # Lifecycle (no old/new or not a "Changed" event)
    if 'Deleted' in msg:
        severity = 'high'
        if 'directory' in msg:
            return 'Directory Deleted', severity
        else:
            return 'File Deleted', severity
    if 'Renamed' in msg or 'Moved' in msg:
        alert_type = 'File Moved / Renamed'
        severity = 'low'
        if 'directory' in msg:
            alert_type = 'Directory Moved / Renamed'
        if changed:
            if not changed:
                return 'File Modified', 'medium'
            # Pick first matching attribute (by priority order)
            severity = 'low'
            alert_type = 'File Modified'
            for key, atype, sev in _ATTR_ALERT_MAP:
                if key in changed:
                    alert_type = atype
                    severity = sev
                    break
            # Multiple attributes changed -> high
            if len(changed) > 1 and severity in ('low', 'medium'):
                severity = 'high'
        return alert_type, severity
    if 'New' in msg or 'untracked' in msg:
        severity = 'medium'
        if 'directory' in msg:
            return 'Directory Created', severity
        else:
            return 'File Created', severity
    if 'Initial change' in msg or 'Changed' in msg:
        if not changed:
            return 'File Modified', 'medium'
        # Pick first matching attribute (by priority order)
        severity = 'low'
        alert_type = 'File Modified'
        for key, atype, sev in _ATTR_ALERT_MAP:
            if key in changed:
                alert_type = atype
                severity = sev
                break
        # Multiple attributes changed -> high
        if len(changed) > 1 and severity in ('low', 'medium'):
            severity = 'high'
        return alert_type, severity
    # Operational / unknown
    if 'Error' in msg or 'Failed' in msg:
        return 'Error', 'high'
    return msg[:40] or 'Alert', 'low'
@app.template_filter('unixtime')
def format_unixtime(value):
    if value is None:
        return ''
    try:
        return datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OSError):
        return str(value)
DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FIM Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-page: #0f1419;
            --bg-sidebar: #161b22;
            --bg-card: #1c2128;
            --bg-row: #21262d;
            --bg-row-alt: #161b22;
            --border: #30363d;
            --text: #e6edf3;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --accent-soft: rgba(88, 166, 255, 0.15);
            --danger: #f85149;
            --danger-soft: rgba(248, 81, 73, 0.15);
            --warn: #d29922;
            --warn-bg: rgba(210, 153, 34, 0.2);
            --radius: 12px;
            --radius-sm: 8px;
            --shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        }
        * { box-sizing: border-box; }
        body {
            font-family: 'IBM Plex Sans', -apple-system, sans-serif;
            margin: 0;
            padding: 0;
            background: var(--bg-page);
            color: var(--text);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }
        .container {
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            width: 260px;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border);
            padding: 24px 0;
            position: fixed;
            height: 100%;
            overflow-y: auto;
        }
        .sidebar h2 {
            margin: 0 20px 24px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
        }
        .sidebar ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .sidebar li { margin: 0; }
        .sidebar a {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.9375rem;
            font-weight: 500;
            display: block;
            padding: 10px 20px;
            margin: 2px 12px;
            border-radius: var(--radius-sm);
            transition: color 0.15s, background 0.15s;
        }
        .sidebar a:hover {
            color: var(--text);
            background: var(--bg-row);
        }
        .main-content {
            flex: 1;
            margin-left: 260px;
            min-width: 0;
            padding: 28px 32px 64px;
            overflow-y: auto;
            background: var(--bg-card);
        }
        .main-content h1 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text);
            margin: 0 0 20px;
            letter-spacing: -0.02em;
        }
        .card {
            background: var(--bg-row-alt);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 20px;
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        th, td {
            padding: 14px 20px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: var(--bg-row);
            color: var(--text-muted);
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        tbody tr {
            background: var(--bg-card);
        }
        tbody tr:nth-child(even) {
            background: var(--bg-row-alt);
        }
        tbody tr:hover {
            background: var(--bg-row);
        }
        td { color: var(--text); }
        .expand {
            cursor: pointer;
            font-weight: 600;
            color: var(--accent);
            font-size: 1rem;
            user-select: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            border-radius: var(--radius-sm);
            background: var(--accent-soft);
            transition: background 0.15s;
        }
        .expand:hover { background: rgba(88, 166, 255, 0.25); }
        .details-row {
            display: none;
        }
        .details-row td {
            padding: 0;
            background: var(--bg-sidebar);
            border-top: 1px solid var(--border);
            vertical-align: top;
        }
        .details-inner {
            max-height: min(70vh, 480px);
            overflow: auto;
            padding: 20px 24px;
        }
        .details-path {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.8125rem;
            color: var(--accent);
            word-break: break-all;
            margin-bottom: 16px;
            padding: 10px 12px;
            background: var(--bg-card);
            border-radius: var(--radius-sm);
            border: 1px solid var(--border);
        }
        .details-row h4 {
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            margin: 16px 0 8px;
        }
        .attr-table-wrap {
            overflow-x: auto;
            border-radius: var(--radius-sm);
            border: 1px solid var(--border);
            margin-bottom: 12px;
        }
        .attr-table {
            width: 100%;
            min-width: 420px;
            border-collapse: collapse;
            font-size: 0.8125rem;
        }
        .attr-table th {
            background: var(--bg-row);
            padding: 10px 12px;
            white-space: nowrap;
        }
        .attr-table td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.75rem;
        }
        .attr-table td.attr-name { width: 90px; min-width: 90px; }
        .attr-table td.attr-old, .attr-table td.attr-new {
            min-width: 140px;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .attr-table td.attr-old { border-right: 1px solid var(--border); }
        .changed {
            background: var(--warn-bg) !important;
            color: var(--warn);
        }
        .changed td { color: var(--text); }
        .alert-type, .log-type {
            font-weight: 600;
            color: var(--accent);
        }
        .sev { font-size: 1rem; line-height: 1; }
        .sev-critical { color: #f85149; }
        .sev-high { color: #db6d28; }
        .sev-medium { color: #d29922; }
        .sev-low { color: #58a6ff; }
        .path-cell { max-width: 280px; }
        .path-text { font-family: 'IBM Plex Mono', monospace; font-size: 0.8125rem; word-break: break-all; }
        .refresh-hint {
            font-size: 0.8125rem;
            color: var(--text-muted);
            margin-top: 16px;
        }
        footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.75rem;
            padding: 16px;
            border-top: 1px solid var(--border);
            background: var(--bg-card);
            margin-left: 260px;
        }
        @media (max-width: 768px) {
            .container { flex-direction: column; }
            .sidebar { width: 100%; height: auto; position: relative; border-right: none; border-bottom: 1px solid var(--border); }
            .main-content { margin-left: 0; padding-bottom: 24px; }
            footer { margin-left: 0; }
        }
    </style>
    <script>
        function toggleDetails(id) {
            var row = document.getElementById('details-' + id);
            var expandBtn = document.getElementById('expand-' + id);
            if (row.style.display === 'none' || row.style.display === '') {
                row.style.display = 'table-row';
                expandBtn.textContent = '-';
            } else {
                row.style.display = 'none';
                expandBtn.textContent = '+';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <nav class="sidebar">
            <h2>FIM Dashboard</h2>
            <ul>
                <li><a href="/logs">Logs</a></li>
                <li><a href="/alerts">Alerts</a></li>
            </ul>
        </nav>
        <div class="main-content">
            {% block content %}{% endblock %}
        </div>
    </div>
    <footer>v0.2.0-alpha</footer>
</body>
</html>
"""
LOGS_CONTENT = """
<h1>All Logs</h1>
<div class="card">
<table>
    <tr><th>Timestamp</th><th>Message</th></tr>
    {% for log in logs %}
    <tr>
        <td>{{ log.timestamp }}</td>
        <td>
            {% if log.details and log.details.path %}
                {% if 'Changed' in log.message or 'Initial change' in log.message %}
                <span class="log-type">File Change:</span> {{ log.details.path }}
                {% elif 'New' in log.message or 'Initial new' in log.message or 'untracked' in log.message %}
                <span class="log-type">New File:</span> {{ log.details.path }}
                {% elif 'Deleted' in log.message %}
                <span class="log-type">File Deleted:</span> {{ log.details.path }}
                {% elif 'Moved' in log.message %}
                <span class="log-type">File Moved:</span> {{ log.details.path }}
                {% else %}
                {{ log.message }}
                {% endif %}
            {% else %}
            {{ log.message }}
            {% endif %}
        </td>
    </tr>
    {% endfor %}
</table>
</div>
<p class="refresh-hint">Refresh to update.</p>
"""
ALERTS_CONTENT = """
<h1>Alerts</h1>
<div class="card">
<table>
    <tr><th>Sev</th><th>Time</th><th>Alert Type</th><th>File Path</th><th></th></tr>
    {% for alert in alerts %}
    <tr>
        <td><span class="sev sev-{{ alert.severity }}" title="{{ alert.severity|upper }}">{% if alert.severity == 'critical' %}&#128308;{% elif alert.severity == 'high' %}&#128992;{% elif alert.severity == 'medium' %}&#128993;{% else %}&#128994;{% endif %}</span></td>
        <td>{{ alert.time_short }}</td>
        <td>{{ alert.alert_type }}</td>
        <td class="path-cell">{% if alert.path %}<span class="path-text">{{ alert.path }}</span>{% else %}&#8212;{% endif %}</td>
        <td>
            {% if alert.details and (alert.details.old or alert.details.new) %}
            <span id="expand-{{ loop.index }}" class="expand" onclick="toggleDetails({{ loop.index }})">+</span>
            {% endif %}
        </td>
    </tr>
    <tr id="details-{{ loop.index }}" class="details-row">
        <td colspan="5">
            {% if alert.details %}
            <div class="details-inner">
                {% if alert.details.old_path and alert.details.new_path %}
                <div class="details-path">{{ alert.details.old_path }} → {{ alert.details.new_path }}</div>
                {% else %}
                <div class="details-path">{{ alert.details.path }}</div>
                {% endif %}
                {% if alert.details.old and alert.details.new %}
                <h4>Attribute changes (old → new)</h4>
                <div class="attr-table-wrap">
                <table class="attr-table">
                    <tr><th class="attr-name">Attribute</th><th>Old value</th><th>New value</th></tr>
                    {% for key in alert.details.old.keys() %}
                    <tr {% if alert.details.old[key] != alert.details.new[key] %}class="changed"{% endif %}>
                        <td class="attr-name">{{ key }}</td>
                        <td class="attr-old" title="{{ alert.details.old[key] if key != 'mtime' else (alert.details.old[key]|unixtime) }}">{% if key == 'mtime' %}{{ alert.details.old[key]|unixtime }}{% else %}{{ alert.details.old[key] }}{% endif %}</td>
                        <td class="attr-new" title="{{ alert.details.new[key] if key != 'mtime' else (alert.details.new[key]|unixtime) }}">{% if key == 'mtime' %}{{ alert.details.new[key]|unixtime }}{% else %}{{ alert.details.new[key] }}{% endif %}</td>
                    </tr>
                    {% endfor %}
                </table>
                </div>
                {% elif alert.details.old %}
                <h4>Old baseline (deleted)</h4>
                <div class="attr-table-wrap">
                <table class="attr-table">
                    <tr><th class="attr-name">Attribute</th><th>Value</th></tr>
                    {% for key, value in alert.details.old.items() %}
                    <tr><td class="attr-name">{{ key }}</td><td class="attr-old" title="{{ value|unixtime if key == 'mtime' else value }}">{% if key == 'mtime' %}{{ value|unixtime }}{% else %}{{ value }}{% endif %}</td></tr>
                    {% endfor %}
                </table>
                </div>
                {% elif alert.details.new %}
                <h4>New attributes</h4>
                <div class="attr-table-wrap">
                <table class="attr-table">
                    <tr><th class="attr-name">Attribute</th><th>Value</th></tr>
                    {% for key, value in alert.details.new.items() %}
                    <tr><td class="attr-name">{{ key }}</td><td class="attr-new" title="{{ value|unixtime if key == 'mtime' else value }}">{% if key == 'mtime' %}{{ value|unixtime }}{% else %}{{ value }}{% endif %}</td></tr>
                    {% endfor %}
                </table>
                </div>
                {% endif %}
            </div>
            {% endif %}
        </td>
    </tr>
    {% endfor %}
</table>
</div>
<p class="refresh-hint">Refresh to update.</p>
"""
@app.route('/logs')
def show_logs():
    logs = get_logs()
    return render_template_string(DASHBOARD_HTML.replace('{% block content %}{% endblock %}', LOGS_CONTENT), logs=logs)
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
@app.route('/alerts')
def show_alerts():
    alerts = get_alerts()
    alerts = _enrich_alerts(alerts)
    return render_template_string(DASHBOARD_HTML.replace('{% block content %}{% endblock %}', ALERTS_CONTENT), alerts=alerts)
  
