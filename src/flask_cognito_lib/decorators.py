from base64 import urlsafe_b64encode
from functools import wraps
from hashlib import sha256
from os import urandom
from typing import Dict

from flask import current_app, jsonify, redirect, request, session
from flask_jwt_extended import (
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies,
    verify_jwt_in_request,
)
from werkzeug.local import LocalProxy

from flask_cognito_lib.config import Config

cfg = Config()
_auth_cls = LocalProxy(lambda: current_app.extensions[cfg.APP_EXTENSION_KEY])


def secure_random(n_bytes: int = 16) -> str:
    """Generate a secure URL-safe random string"""
    return urlsafe_b64encode(urandom(n_bytes)).decode("utf-8")


def update_session(state: Dict[str, str]):
    """Update the Flask session with key/value pairs"""
    session.update(state)


def cognito_login(fn):
    """A decorator that redirects to the Cognito hosted UI"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # store parameters in the session that are passed to Cognito
        # and required for JWT verification
        code_verifier = secure_random()
        cognito_session = {
            "code_verifier": code_verifier,
            "code_challenge": sha256(code_verifier.encode("utf-8")).hexdigest(),
            "nonce": secure_random(),
            "state": secure_random(),
        }
        update_session(cognito_session)

        # TODO add support for scopes
        res = redirect(
            _auth_cls.cognito_service.get_sign_in_url(
                code_challenge=cognito_session["code_challenge"],
                nonce=cognito_session["nonce"],
                state=cognito_session["state"],
            )
        )

        return res

    return wrapper


def cognito_login_callback(fn):
    """
    A decorator to wrap the redirect after a user has logged in with Cognito.
    Stores the Cognito JWT in a http only cookie.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Get the access token return after auth flow with Cognito
        code_verifier = session["code_verifier"]
        state = session["state"]
        code_challenge = session["code_challenge"]
        nonce = session["nonce"]

        # exchange the code for an access token
        access_token = _auth_cls.get_token(
            request_args=request.args,
            expected_state=state,
            code_verifier=code_verifier,
        )

        # validate the JWT
        claims = _auth_cls.decode_and_verify_token(
            token=access_token,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            nonce=nonce,
            state=state,
        )

        update_session({"claims": claims})

        # return and set the JWT as a http only cookie
        resp = fn(*args, **kwargs)
        set_access_cookies(resp, access_token, max_age=30 * 60)  # TODO config
        return resp

    return wrapper


def cognito_logout(fn):
    """A decorator that handles logging out with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # remove the congito vars from the session
        update_session(
            {
                "code_verifier": None,
                "code_challenge": None,
                "nonce": None,
                "state": None,
                "claims": None,
            }
        )

        # logout at cognito and remove the cookies
        res = redirect(cfg.logout_endpoint)
        unset_jwt_cookies(res)
        return res

    return wrapper


def auth_required():
    """A decorator to protect a route with AWS Cognito"""

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(optional=True)
            if get_jwt_identity():
                return fn(*args, **kwargs)
            else:
                return jsonify("Not authorised"), 403

        return decorator

    return wrapper


# TODO implement these
# def groups_required(groups: List[str]):
#     """View decorator that requires a the user to in one or more Cognito groups."""

#     def decorator(function):
#         @wraps(function)
#         def wrapper(*args, **kwargs):
#             _check_groups(groups)
#             return function(*args, **kwargs)

#         return wrapper

#     return decorator

# def _check_groups(groups: List[str]):
#     pass
