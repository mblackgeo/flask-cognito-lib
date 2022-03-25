from typing import Any, List, Optional
from urllib.parse import quote

from flask import current_app

from .exceptions import ConfigurationError


def get(key: str, required: bool = False, default: Optional[Any] = None) -> Any:
    """Get a key from the current Flask application's configuration

    Parameters
    ----------
    key : str
        Name of key
    required : bool, optional
        Set whether it is required, by default False
    default : Optional[Any], optional
        A default value for `required=False` keys that are not already in the
        app config, by default None

    Returns
    -------
    Any
        The value of the configuration `key`

    Raises
    ------
    CognitoConfigurationError
        If key is required but no in the current app configuration
    """
    if key not in current_app.config and required:
        raise ConfigurationError("Missing required configuration parameter: ", key)

    if key not in current_app.config:
        return default

    return current_app.config[key]


class Config:
    """
    Helper class to hold the congfiguration
    """

    # Constants
    APP_EXTENSION_KEY = "cognito_auth_lib"
    CONTEXT_KEY_COGNITO_SERVICE = "aws_cognito_service"
    CONTEXT_KEY_TOKEN_SERVICE = "aws_jwt_service"
    COOKIE_NAME = "cognito_access_token"

    @property
    def user_pool_id(self) -> str:
        """Return the Cognito user pool ID"""
        return get("AWS_COGNITO_USER_POOL_ID", required=True)

    @property
    def user_pool_client_id(self) -> str:
        """Return the Cognito user pool client ID"""
        return get("AWS_COGNITO_USER_POOL_CLIENT_ID", required=True)

    @property
    def user_pool_client_secret(self) -> str:
        """Return the Cognito user pool client secret"""
        return get("AWS_COGNITO_USER_POOL_CLIENT_SECRET", required=True)

    @property
    def redirect_url(self) -> str:
        """Return the Redirect URL (post-login)"""
        return get("AWS_COGNITO_REDIRECT_URL", required=True)

    @property
    def logout_redirect(self) -> str:
        """Return the Redirect URL (post-logout)"""
        return get("AWS_COGNITO_LOGOUT_URL", required=True)

    @property
    def domain(self) -> str:
        """Return the Cognito domain"""
        return get("AWS_COGNITO_DOMAIN", required=True)

    @property
    def region(self) -> str:
        """Return the AWS region"""
        return get("AWS_REGION", required=True)

    @property
    def max_cookie_age_seconds(self) -> int:
        """Return maximum age to keep an access token cookie for, in seconds"""
        return int(get("AWS_COGNITO_COOKIE_AGE_SECONDS", required=False, default=1800))

    @property
    def cognito_expiration_leeway(self) -> int:
        """Return the leeway (in seconds) for checking token expiration

        This is here largely for testing purposes. In production applications
        this should be set to zero.
        """
        return int(get("AWS_COGNITO_EXPIRATION_LEEWAY", required=False, default=0))

    @property
    def cognito_scopes(self) -> Optional[List[str]]:
        """
        Return the scopes to request from Cognito.
        If None, all supported scopes are returned
        """
        return get("AWS_COGNITO_SCOPES", required=False, default=None)

    @property
    def issuer(self) -> str:
        """Return the issuer"""
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    @property
    def jwk_endpoint(self) -> str:
        """Return the endpoint that holds the JWKs"""
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def token_endpoint(self) -> str:
        """Return the Cognito TOKEN endpoint URL"""
        return f"{self.domain}/oauth2/token"

    @property
    def authorize_endpoint(self) -> str:
        """Return the Cognito AUTHORIZE endpoint URL"""
        return f"{self.domain}/oauth2/authorize"

    @property
    def logout_endpoint(self) -> str:
        """Return the Cognito LOGOUT endpoint URL"""
        return (
            f"{self.domain}/logout"
            f"?client_id={self.user_pool_client_id}"
            f"&logout_uri={quote(self.logout_redirect)}"
        )

    @property
    def user_info_endpoint(self) -> str:
        """Return the Cognito USERINFO endpoint URL"""
        return f"{self.domain}/oauth2/userInfo"

    @property
    def revoke_endpoint(self) -> str:
        """Return the Cognito REVOKE endpoint URL"""
        return f"{self.domain}/oauth2/revoke"
