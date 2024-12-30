from typing import Any, Callable, Dict, Optional

from flask import Flask, g

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
        cfg: Optional[Config] = None,
    ):
        """Instantiate the CognitoAuth manager

        Parameters
        ----------
        app : Optional[Flask], optional
            An optional instance of a Flask application. If doing lazy init
            use the `init_app` method instead
        cfg : Optional[Config], optional
            Configuration object to use. If not provided, a default Config is used.
        """
        self.token_service_factory = _token_service_factory
        self.cognito_service_factory = _cognito_service_factory
        if app is not None:
            self.init_app(app=app, cfg=cfg)

    def init_app(self, app: Flask, cfg: Optional[Config] = None):
        """Register the extension with a Flask application

        Parameters
        ----------
        app : Flask
            Flask application
        cfg : Optional[Config], optional
            Configuration object to use. If not provided, a default Config is used.
        """
        if cfg:
            self.cfg = cfg
        else:
            self.cfg = Config()
        app.extensions[self.cfg.APP_EXTENSION_KEY] = self

    @property
    def token_service(self) -> TokenService:
        """Instantiate an instance of the TokenService within the app context

        Returns
        -------
        TokenService
            An instance of TokenService
        """
        if not hasattr(g, self.cfg.CONTEXT_KEY_TOKEN_SERVICE):
            token_service = self.token_service_factory(cfg=self.cfg)
            setattr(g, self.cfg.CONTEXT_KEY_TOKEN_SERVICE, token_service)
        return getattr(g, self.cfg.CONTEXT_KEY_TOKEN_SERVICE)

    @property
    def cognito_service(self) -> CognitoService:
        """Instantiate an instance of the CognitoService within the app context

        Returns
        -------
        CognitoService
            An instance of CognitoService
        """
        if not hasattr(g, self.cfg.CONTEXT_KEY_COGNITO_SERVICE):
            cognito_service = self.cognito_service_factory(cfg=self.cfg)
            setattr(g, self.cfg.CONTEXT_KEY_COGNITO_SERVICE, cognito_service)
        return getattr(g, self.cfg.CONTEXT_KEY_COGNITO_SERVICE)

    def get_tokens(
        self,
        request_args: Dict[str, str],
        expected_state: str,
        code_verifier: str,
    ) -> CognitoTokenResponse:
        """Exchange a short lived authorisation code for with Cognito for tokens

        Parameters
        ----------
        request_args : Dict[str, str]
            Request arguments returned from Cognito in the front channel
            i.e. URL query parameters. Should contain "code" and "state"
        expected_state : str
            The state value that was passed to Cognito when redirecting to the
            Cognito hosted UI. It should be returned unchanged in the
            ``request_args``
        code_verifier : str
            The plaintext code verification secret used as the code challenge
            when logging in

        Returns
        -------
        CognitoTokenResponse
            A dataclass that holds the token response from Cognito

        Raises
        ------
        CognitoError
            If access code or state or not in ``request_args``
            If the state value does not match the expected value
            If the request to the TOKEN endpoint fails
            If the TOKEN endpoint returns an error code
        """
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

    def exchange_refresh_token(
        self,
        refresh_token: str,
    ) -> CognitoTokenResponse:
        """Exchange a refresh token for a new set of tokens

        Parameters:
        -----------
        refresh_token : str
            The refresh token to exchange for a new set of tokens

        Returns:
        --------
        CognitoTokenResponse
            A dataclass that holds the token response from Cognito

        Raises:
        -------
        CognitoError
            If the request to the TOKEN endpoint fails
            If the TOKEN endpoint returns an error code
        """
        return self.cognito_service.exhange_refresh_token(
            refresh_token=refresh_token,
        )

    def revoke_refresh_token(
        self,
        refresh_token: str,
    ) -> None:
        """Revoke a refresh token

        Parameters:
        -----------
        refresh_token : str
            The refresh token to revoke

        Raises:
        -------
        CognitoError
            If the token isn't present in the request or
                if the feature is disabled for the app client
            If the token isn't a refresh token
            If the client credentials aren't valid
        """
        self.cognito_service.revoke_refresh_token(
            refresh_token=refresh_token,
        )

    def verify_access_token(self, token: str, leeway: float) -> Dict[str, Any]:
        """Verify the claims & signature of an access token in JWT format from Cognito

        This will check the audience, issuer, expiry and validate the signature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        access_token : str
            The encoded JWT
        leeway : float
            A time margin in seconds for the expiration check

        Returns
        -------
        Dict[str, Any]
            The verified claims from the encoded JWT

        Raises
        ------
        TokenVerifyError
            If not token is passed, or any checks fail
        """
        return self.token_service.verify_access_token(token=token, leeway=leeway)

    def verify_id_token(
        self,
        token: str,
        leeway: float,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify the claims & signature of an id token in JWT format from Cognito

        This will check the audience, issuer, expiry and validate the signature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        token : str
            The encoded JWT
        leeway : float
            A time margin in seconds for the expiration check
        nonce : Optional[str]
            An optional nonce value to validate to prevent replay attacks

        Returns
        -------
        Dict[str, Any]
            The OIDC claims from the encoded JWT

        Raises
        ------
        TokenVerifyError
            If not token is passed, or any checks fail
        """
        return self.token_service.verify_id_token(
            token=token,
            leeway=leeway,
            nonce=nonce,
        )
