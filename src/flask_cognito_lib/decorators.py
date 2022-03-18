from functools import wraps
from typing import List

from flask import current_app
from werkzeug.local import LocalProxy

from flask_cognito_lib.config import Config

cfg = Config()
_auth_cls = LocalProxy(lambda: current_app.extensions[cfg.APP_EXTENSION_KEY])


def cognito_login_handler():
    # TODO a handler that will redirect to the Cognito Hosted UI
    pass


def cognito_login_callback():
    # TODO set a HTTPOnly cookie after login
    pass


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
