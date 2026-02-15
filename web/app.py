"""Flask app: creation, config, template folder, and blueprint registration."""
import os
from datetime import datetime
from flask import Flask

from web.auth import ensure_default_admin

_root = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
             template_folder=os.path.join(_root, 'templates'),
             static_folder=os.path.join(_root, 'static'),
             static_url_path='/static')
app.secret_key = 'fim-web-secret-change-in-production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


@app.template_filter('unixtime')
def format_unixtime(value):
    if value is None:
        return ''
    try:
        return datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OSError):
        return str(value)


def _ensure_db_and_admin():
    from components.utils import init_db
    init_db()
    ensure_default_admin()


# Register blueprint after app is created to avoid circular import
from web.routes import bp
app.register_blueprint(bp)

# Ensure users table and default admin exist on first request (or we could do at import time)
with app.app_context():
    _ensure_db_and_admin()
