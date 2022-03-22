from typing import Any, Dict
from urllib.error import HTTPError

import jwt
from jwt import PyJWK, PyJWKClient, PyJWKClientError

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError


class TokenService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.jwk = PyJWKClient(self.cfg.jwk_endpoint, cache_keys=True)

    def get_public_key(self, token: str) -> PyJWK:
        """Find the public key ID for a given JWT"""
        try:
            return self.jwk.get_signing_key_from_jwt(token)
        except (PyJWKClientError, HTTPError) as err:
            raise CognitoError("Error getting public keys from Cognito") from err

    def verify(
        self,
        token: str,
        leeway: float = 0,
    ) -> Dict[str, Any]:
        """Verify the content and signature of a JWT from Cognito

        This will check the audience, issuer, expiry and validate the signature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        token : str
            The encoded JWT

        Returns
        -------
        Dict[str, Any]
            The verified claims from the encoded JWT
        leeway
            A time margin in seconds for the expiration check

        Raises
        ------
        TokenVerifyError
            If not token is passed, or any checks fail
        """
        if not token:
            raise TokenVerifyError("No token provided")

        try:
            claims = jwt.decode(
                jwt=token,
                key=self.get_public_key(token).key,
                algorithms=["RS256"],
                audience=self.cfg.user_pool_client_id,
                issuer=self.cfg.issuer,
                leeway=leeway,
                options={
                    "verify_signature": True,
                    "verify_aud": False,  # JWT from Cognito will set client_id
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )

        except jwt.PyJWTError as err:
            raise TokenVerifyError("Token is not valid") from err

        # Cognito does not set an audience, but should populate client_id
        try:
            if claims["client_id"] != self.cfg.user_pool_client_id:
                raise TokenVerifyError("Token was not issued for this client id")

        except KeyError as err:
            raise TokenVerifyError("Token is missing client id") from err

        return claims
