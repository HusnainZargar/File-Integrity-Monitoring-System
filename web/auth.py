"""Authentication: PBKDF2 password hashing via werkzeug, session, DB-backed users."""
from functools import wraps
from flask import session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from components.utils import (
    get_user,
    update_user_password,
    create_user,
    user_count,
    update_last_login,
    update_username,
)


def hash_password(password):
    """Return a salted PBKDF2 hash of the password."""
    return generate_password_hash(password)


def verify_user(username, password):
    """Return True if username exists and password matches stored hash."""
    user = get_user(username)
    if not user:
        return False
    return check_password_hash(user['password_hash'], password)


def update_login_timestamp(username):
    update_last_login(username)


def ensure_default_admin():
    """Seed admin user on first run. Uses secure hash."""
    if user_count() > 0:
        return
    create_user('admin', hash_password('admin'))


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return wrapped


def change_password_for_user(username, current_password, new_password):
    """
    Returns (True, None) on success, (False, 'error message') on failure.
    """
    if not verify_user(username, current_password):
        return False, 'Current password is incorrect.'
    if not new_password or len(new_password) < 6:
        return False, 'New password must be at least 6 characters.'
    update_user_password(username, hash_password(new_password))
    return True, None


def change_username_for_user(current_username, new_username, password):
    """
    Returns (True, None) on success, (False, 'error message') on failure.
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
