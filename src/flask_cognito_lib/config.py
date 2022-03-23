from typing import Any, Optional
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
        return get("AWS_COGNITO_USER_POOL_ID", required=True)

    @property
    def user_pool_client_id(self) -> str:
        return get("AWS_COGNITO_USER_POOL_CLIENT_ID", required=True)

    @property
    def user_pool_client_secret(self) -> str:
        return get("AWS_COGNITO_USER_POOL_CLIENT_SECRET", required=True)

    @property
    def redirect_url(self) -> str:
        return get("AWS_COGNITO_REDIRECT_URL", required=True)

    @property
    def logout_redirect(self) -> str:
        return get("AWS_COGNITO_LOGOUT_URL", required=True)

    @property
    def domain(self) -> str:
        return get("AWS_COGNITO_DOMAIN", required=True)

    @property
    def region(self) -> str:
        return get("AWS_REGION", required=True)

    @property
    def max_cookie_age_seconds(self) -> int:
        return int(get("AWS_COGNITO_COOKIE_AGE_SECONDS", required=False, default=1800))

    @property
    def cognito_response_leeway(self) -> int:
        return int(get("AWS_COGNITO_RESPONSE_LEEWAY", required=False, default=10))

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    @property
    def jwk_endpoint(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def token_endpoint(self) -> str:
        return f"{self.domain}/oauth2/token"

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.domain}/oauth2/authorize"

    @property
    def logout_endpoint(self) -> str:
        return (
            f"{self.domain}/logout"
            f"?client_id={self.user_pool_client_id}"
            f"&logout_uri={quote(self.logout_redirect)}"
        )

    @property
    def user_info_endpoint(self) -> str:
        return f"{self.domain}/oauth2/userInfo"

    @property
    def revoke_endpoint(self) -> str:
        return f"{self.domain}/oauth2/revoke"
