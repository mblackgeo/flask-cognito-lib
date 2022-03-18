from typing import Callable, Optional

from flask import Flask
from flask import _app_ctx_stack as ctx_stack

from flask_cognito_lib.config import Config
from flask_cognito_lib.services import cognito_service_factory, token_service_factory


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
    def token_service(self):
        ctx = ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE):
                token_service = self.token_service_factory(
                    user_pool_id=self.cfg.user_pool_id,
                    user_pool_client_id=self.cfg.user_pool_client_id,
                    region=self.cfg.region,
                )
                setattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE, token_service)
            return getattr(ctx, self.cfg.CONTEXT_KEY_TOKEN_SERVICE)

    @property
    def cognito_service(self):
        ctx = ctx_stack.top
        if ctx is not None:
            if not hasattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE):
                cognito_service = self.cognito_service_factory(
                    user_pool_id=self.cfg.user_pool_id,
                    user_pool_client_id=self.cfg.user_pool_client_id,
                    user_pool_client_secret=self.cfg.user_pool_client_secret,
                    redirect_url=self.cfg.redirect_url,
                    region=self.cfg.region,
                    domain=self.cfg.domain,
                )
                setattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE, cognito_service)
            return getattr(ctx, self.cfg.CONTEXT_KEY_COGNITO_SERVICE)
