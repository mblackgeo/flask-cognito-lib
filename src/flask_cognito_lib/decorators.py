from functools import wraps
from typing import Iterable, Optional, Union

from flask import Response
from flask import current_app as app
from flask import redirect, request, session
from werkzeug.local import LocalProxy

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import (
    AuthorisationRequiredError,
    CognitoError,
    CognitoGroupRequiredError,
    TokenVerifyError,
)
from flask_cognito_lib.plugin import CognitoAuth
from flask_cognito_lib.utils import (
    CognitoTokenResponse,
    generate_code_challenge,
    generate_code_verifier,
    secure_random,
)

cfg = Config()
cognito_auth: CognitoAuth = LocalProxy(
    lambda: app.extensions[cfg.APP_EXTENSION_KEY]
)  # type: ignore


def remove_from_session(keys: Iterable[str]):
    """Remove an entry from the session"""
    with app.app_context():
        for key in keys:
            if key in session:
                session.pop(key)


def store_tokens(tokens: CognitoTokenResponse, nonce: Optional[str] = None) -> None:
    """Store the tokens in the session"""
    # validate the JWT and get the claims
    claims = cognito_auth.verify_access_token(
        token=tokens.access_token,
        leeway=cfg.cognito_expiration_leeway,
    )
    session.update({"claims": claims})

    # Grab the user info from the user endpoint and store in the session
    if tokens.id_token is not None:
        user_info = cognito_auth.verify_id_token(
            token=tokens.id_token,
            nonce=nonce,
            leeway=cfg.cognito_expiration_leeway,
        )
        session.update({"user_info": user_info})


def store_token_in_cookie(
    token: Union[str, None],
    cookie_name: str,
    resp: Response,
    encrypt: bool = False,
) -> None:
    if encrypt:
        # Encrypt the token
        token = cognito_auth.token_service.encrypt_token(token)

    """Store the access token in a HTTP only secure cookie"""
    resp.set_cookie(
        key=cookie_name,
        value=token,
        max_age=cfg.max_cookie_age_seconds,
        httponly=True,
        secure=True,
        samesite=cfg.cookie_samesite,
        domain=cfg.cookie_domain,
    )


def get_token_from_cookie(cookie_name: str) -> Union[str, None]:
    """Get the token from the cookie"""
    token = request.cookies.get(cookie_name)

    if (
        token
        and cfg.COOKIE_NAME_REFRESH == cookie_name
        and cfg.refresh_cookie_encrypted
    ):
        # Decrypt the refresh token
        return cognito_auth.token_service.decrypt_token(token)

    return token


def cognito_login(fn):
    """A decorator that redirects to the Cognito hosted UI"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        with app.app_context():
            # store parameters in the session that are passed to Cognito
            # and required for JWT verification
            code_verifier = generate_code_verifier()
            cognito_session = {
                "code_verifier": code_verifier,
                "code_challenge": generate_code_challenge(code_verifier),
                "nonce": secure_random(),
            }
            session.update(cognito_session)

            # Add suport for custom state values which are appended to a secure
            # random value for additional CRSF protection
            state = secure_random()
            custom_state = session.get("state")
            if custom_state:
                state += f"__{custom_state}"

            session.update({"state": state})

            login_url = cognito_auth.cognito_service.get_sign_in_url(
                code_challenge=session["code_challenge"],
                state=session["state"],
                nonce=session["nonce"],
                scopes=cfg.cognito_scopes,
            )

        return redirect(login_url)

    return wrapper


def cognito_login_callback(fn):
    """
    A decorator to wrap the redirect after a user has logged in with Cognito.
    Stores the Cognito JWT in a http only cookie.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        with app.app_context():
            # Get the access token return after auth flow with Cognito
            code_verifier = session["code_verifier"]
            state = session["state"]
            nonce = session["nonce"]

            # exchange the code for an access token
            # also confirms the returned state is correct
            tokens = cognito_auth.get_tokens(
                request_args=request.args,
                expected_state=state,
                code_verifier=code_verifier,
            )

            # Store the tokens in the session
            store_tokens(tokens=tokens, nonce=nonce)

            # Remove one-time use variables now we have completed the auth flow
            remove_from_session(("code_challenge", "code_verifier", "nonce"))

            # split out the random part of the state value (in case the user
            # specified their own custom state value)
            state = session.get("state").split("__")[-1]
            session.update({"state": state})

            # return and set the JWT as a http only cookie
            resp = fn(*args, **kwargs)

            # Store the access token in a HTTP only secure cookie
            store_token_in_cookie(
                token=tokens.access_token,
                cookie_name=cfg.COOKIE_NAME,
                resp=resp,
            )

            # Grab the refresh token and store in a HTTP only secure cookie
            if cfg.refresh_flow_enabled and tokens.refresh_token:
                store_token_in_cookie(
                    token=tokens.refresh_token,
                    cookie_name=cfg.COOKIE_NAME_REFRESH,
                    resp=resp,
                    encrypt=cfg.refresh_cookie_encrypted,
                )

        return resp

    return wrapper


def cognito_refresh_callback(fn):
    """A decorator that handles token refresh with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        with app.app_context():
            if not cfg.refresh_flow_enabled:
                raise CognitoError("Refresh flow is not enabled")

            refresh_token = get_token_from_cookie(cfg.COOKIE_NAME_REFRESH)

            if not refresh_token:
                raise CognitoError("No refresh token provided")

            # Exchange refresh token for the new access token.
            tokens = cognito_auth.refresh_tokens(
                refresh_token=refresh_token,
            )

            # Store the tokens in the session
            store_tokens(tokens=tokens)

            # Return and set the JWT as a http only cookie
            resp = fn(*args, **kwargs)

            # Store the access token in a HTTP only secure cookie
            store_token_in_cookie(
                token=tokens.access_token,
                cookie_name=cfg.COOKIE_NAME,
                resp=resp,
            )

            # Grab the refresh token and store in a HTTP only secure cookie
            if cfg.refresh_flow_enabled and tokens.refresh_token is not None:
                store_token_in_cookie(
                    token=tokens.refresh_token,
                    cookie_name=cfg.COOKIE_NAME_REFRESH,
                    resp=resp,
                    encrypt=cfg.refresh_cookie_encrypted,
                )

        return resp

    return wrapper


def cognito_logout(fn):
    """A decorator that handles logging out with Cognito"""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        with app.app_context():
            # logout at cognito and remove the cookies
            resp = redirect(cfg.logout_endpoint)
            resp.delete_cookie(key=cfg.COOKIE_NAME, domain=cfg.cookie_domain)

            # Revoke the refresh token if it exists
            if refresh_token := get_token_from_cookie(cfg.COOKIE_NAME_REFRESH):
                cognito_auth.revoke_refresh_token(refresh_token)
                resp.delete_cookie(
                    key=cfg.COOKIE_NAME_REFRESH,
                    domain=cfg.cookie_domain,
                )

        # Cognito will redirect to the sign-out URL (if set) or else use
        # the callback URL
        return resp

    return wrapper


def auth_required(groups: Optional[Iterable[str]] = None, any_group: bool = False):
    """A decorator to protect a route with AWS Cognito"""

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            with app.app_context():
                # return early if the extension is disabled
                if cfg.disabled:
                    return fn(*args, **kwargs)

                # Try and validate the access token stored in the cookie
                try:
                    access_token = request.cookies.get(cfg.COOKIE_NAME)
                    claims = cognito_auth.verify_access_token(
                        token=access_token,
                        leeway=cfg.cognito_expiration_leeway,
                    )
                    valid = True

                    # Check for required group membership
                    if groups:
                        if any_group:
                            valid = any(g in claims["cognito:groups"] for g in groups)
                        else:
                            valid = all(g in claims["cognito:groups"] for g in groups)

                        if not valid:
                            raise CognitoGroupRequiredError

                except (TokenVerifyError, KeyError):
                    valid = False

                if valid:
                    return fn(*args, **kwargs)

                raise AuthorisationRequiredError

        return decorator

    return wrapper
