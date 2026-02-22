"""Authentication: SHA256 password hashing, session, and DB-backed users."""
import hashlib
from functools import wraps
from flask import session, redirect, url_for

from components.utils import get_user, update_user_password, create_user, user_count, update_last_login, update_username


def hash_password(password):
    """Return SHA256 hex digest of password (UTF-8 encoded)."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_user(username, password):
    """Return True if username exists and password hash matches."""
    user = get_user(username)
    if not user:
        return False
    return user['password_hash'] == hash_password(password)


def update_login_timestamp(username):
    """Call after successful login."""
    update_last_login(username)


def ensure_default_admin():
    """If no users exist, create admin with default password (hashed). One-time seed only."""
    if user_count() > 0:
        return
    # Seed: only place we use a default; stored as hash, never compared as plain text
    default_password_hash = hash_password('admin')
    create_user('admin', default_password_hash)


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return wrapped


def change_password_for_user(username, current_password, new_password):
    """
    Update password for username. Returns (True, None) on success,
    (False, 'error message') on failure.
    """
    if not verify_user(username, current_password):
        return False, 'Current password is incorrect.'
    if not new_password or len(new_password) < 6:
        return False, 'New password must be at least 6 characters.'
    new_hash = hash_password(new_password)
    update_user_password(username, new_hash)
    return True, None


def change_username_for_user(current_username, new_username, password):
    """
    Change username. Returns (True, None) on success, (False, 'error message') on failure.
    """
    if not verify_user(current_username, password):
        return False, 'Password is incorrect.'
    new_username = (new_username or '').strip()
    if not new_username:
        return False, 'New username cannot be empty.'
    if new_username == current_username:
        return False, 'New username is the same as current.'
    if not update_username(current_username, new_username):
        return False, 'Username already taken.'
    return True, None
