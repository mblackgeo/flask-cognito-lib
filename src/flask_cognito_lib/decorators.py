from functools import wraps
from typing import List

from flask import current_app, redirect, request
from flask_jwt_extended import set_access_cookies, unset_jwt_cookies
from werkzeug.local import LocalProxy

from flask_cognito_lib.config import Config

cfg = Config()
_auth_cls = LocalProxy(lambda: current_app.extensions[cfg.APP_EXTENSION_KEY])


def cognito_login(fn):
    """A decorator that redirects to the Cognito hosted UI"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        res = redirect(cfg.login_endpoint)
        return res

    return wrapper


def cognito_login_callback(fn):
    """
    A decorator to wrap the redirect after a user has logged in with Cognito.
    Stores the Cognito JWT in a http only cookie.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        access_token = _auth_cls.get_access_token(request.args)
        resp = fn(*args, **kwargs)
        set_access_cookies(resp, access_token, max_age=30 * 60)  # TODO config
        return resp

    return wrapper


def cognito_logout(fn):
    """A decorator that handles logging out with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        res = redirect(cfg.logout_endpoint)
        unset_jwt_cookies(res)
        return res

    return wrapper


def auth_required(fn):
    """View decorator that requires a valid Cognito JWT cookie."""

    @wraps(fn)
    def decorator(*args, **kwargs):
        _check_auth()
        return fn(*args, **kwargs)

    return decorator


def groups_required(groups: List[str]):
    """View decorator that requires a the user to in one or more Cognito groups."""

    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            _check_groups(groups)
            return function(*args, **kwargs)

        return wrapper

    return decorator


def _check_auth():
    # TODO
    pass


def _check_groups(groups: List[str]):
    pass
