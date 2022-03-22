from typing import Callable, Dict, Optional

from flask import Flask
from flask import _app_ctx_stack as ctx_stack

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError
from flask_cognito_lib.services import cognito_service_factory, token_service_factory
from flask_cognito_lib.services.cognito_svc import CognitoService
from flask_cognito_lib.services.token_svc import TokenService
from flask_cognito_lib.utils import CognitoTokenResponse


class CognitoAuth:
    def __init__(
        self,
        app: Optional[Flask] = None,
        _token_service_factory: Callable = token_service_factory,
        _cognito_service_factory: Callable = cognito_service_factory,
    ):
        """Instantiate the CognitoAuth manager

        Parameters
        ----------
        app : Optional[Flask], optional
            An optional instance of a Flask application. If doing lazy init
            use the `init_app` method instead
        """
        self.token_service_factory = _token_service_factory
        self.cognito_service_factory = _cognito_service_factory
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Register the extension with a Flask application

        Parameters
        ----------
        app : Flask
            Flask application
        """
        if not hasattr(app, "extensions"):
            app.extensions = {}

        self.cfg = Config()
        app.extensions[self.cfg.APP_EXTENSION_KEY] = self

    @property
    def token_service(self) -> TokenService:
        # TODO docstring
        ctx = ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE):
                token_service = self.token_service_factory(cfg=self.cfg)
                setattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE, token_service)
            return getattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE)

    @property
    def cognito_service(self) -> CognitoService:
        # TODO docstring
        ctx = ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE):
                cognito_service = self.cognito_service_factory(cfg=self.cfg)
                setattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE, cognito_service)
            return getattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE)

    def get_tokens(
        self, request_args: Dict[str, str], expected_state: str, code_verifier: str
    ) -> CognitoTokenResponse:
        """Get the token from the Cognito redirect after the user has logged in"""
        # TODO docstring
        try:
            code = request_args["code"]
            state = request_args["state"]
        except KeyError as err:
            raise CognitoError(
                "Access code and/or state not returned from Cognito"
            ) from err

        if state != expected_state:
            raise CognitoError("State for CSRF is not correct")

        return self.cognito_service.exchange_code_for_token(
            code=code,
            code_verifier=code_verifier,
        )

    def verify_access_token(self, token: str, leeway: float) -> Dict[str, str]:
        # TODO docstring
        return self.token_service.verify_access_token(token=token, leeway=leeway)

    def verify_id_token(
        self,
        token: str,
        leeway: float,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        # TODO docstring
        return self.token_service.verify_id_token(
            token=token, leeway=leeway, nonce=nonce
        )
