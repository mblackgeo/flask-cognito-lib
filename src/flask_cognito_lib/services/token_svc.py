from base64 import urlsafe_b64encode
from hashlib import sha256
from typing import Any, Dict, Iterable, Optional
from urllib.error import HTTPError

import jwt
from cryptography.fernet import Fernet
from jwt import PyJWK, PyJWKClient, PyJWKClientError

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError


class TokenService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.jwk = PyJWKClient(self.cfg.jwk_endpoint, cache_keys=True)
        self.fernet = Fernet(
            urlsafe_b64encode(sha256(cfg.secret_key.encode()).digest()),
        )

    def get_public_key(self, token: str) -> PyJWK:
        """Find the public key ID for a given JWT

        Parameters
        ----------
        token : str
            The access token in JWT format. Must have `kid` in headers.

        Returns
        -------
        PyJWK
            A PyJWK instance that contains the public information

        Raises
        ------
        CognitoError
            If the PyJWTClient raises or the request to the user pool JWK
            endpoint fails
        """
        try:
            return self.jwk.get_signing_key_from_jwt(token)
        except (PyJWKClientError, HTTPError) as err:
            raise CognitoError("Error getting public keys from Cognito") from err

    def _jwt_validate(
        self,
        token: str,
        options: Dict[str, bool],
        leeway: float = 0,
        required: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Validate the contents and claims of a JSON Web Token (JWT)

        Parameters
        ----------
        token : str
            Token in JWT format
        leeway : float, optional
            Leeway in seconds if validating expiry, by default 0
        options : Dict[str, bool]
            extended decoding and validation options, by default None
            See ``pyjwt.jwt.decode`` for options.
        required : Iterable[str], optional
            List of claims that must be present.
            Will set "aud", "iss", "exp", "iat" by default.

        Returns
        -------
        Dict[str, Any]
            Verified claims from the JWT

        Raises
        ------
        TokenVerifyError
            If claims or signature are invalid
        """
        try:
            claims = jwt.decode(
                jwt=token,
                key=self.get_public_key(token).key,
                algorithms=["RS256"],
                audience=self.cfg.user_pool_client_id,
                issuer=self.cfg.issuer,
                leeway=leeway,
                options=options,
                required=required or ["aud", "iss", "exp", "iat"],
            )

        except jwt.PyJWTError as err:
            raise TokenVerifyError("Token is not valid") from err

        return claims

    def verify_access_token(
        self,
        token: str,
        leeway: float = 0,
    ) -> Dict[str, Any]:
        """Verify the claims & signature of a JWT access token from Cognito

        This will check the audience, issuer, expiry and validate the signature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        access_token : str
            The encoded JWT from Cognito
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
        if not token:
            raise TokenVerifyError("No token provided")

        # Verify the contents and signature of the JWT
        claims = self._jwt_validate(
            token=token,
            leeway=leeway,
            options={
                "verify_signature": True,
                "verify_aud": False,  # JWT from Cognito will set client_id
                "verify_iss": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": False,  # Not issued
            },
        )

        # Cognito does not set an audience, but should populate client_id
        if claims["client_id"] != self.cfg.user_pool_client_id:
            raise TokenVerifyError("Token was not issued for this client id")

        return claims

    def verify_id_token(
        self,
        token: str,
        leeway: float = 0,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify the claims & signature of an id token in JWT format from Cognito

        This will check the audience, issuer, expiry and validate the signature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        token : str
            The encoded JWT
        leeway : flaot
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
        if not token:
            raise TokenVerifyError("No token provided")

        # Verify the contents and signature of the JWT
        claims = self._jwt_validate(
            token=token,
            leeway=leeway,
            options={
                "verify_signature": True,
                "verify_aud": True,  # ID token does contain correct audience
                "verify_iss": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": False,  # Not issued
            },
        )

        # Check nonce value to prevent replay attacks
        if nonce and claims["nonce"] != nonce:
            raise TokenVerifyError("Token nonce check failed")

        return claims

    def encrypt_token(self, token: str) -> str:
        """Encrypt a token using the configured key

        Parameters
        ----------
        token : str
            The token to encrypt

        Returns
        -------
        str
            The encrypted token
        """
        return self.fernet.encrypt(token.encode()).decode()

    def decrypt_token(self, token: str) -> str:
        """Decrypt a token using the configured key

        Parameters
        ----------
        token : str
            The token to decrypt

        Returns
        -------
        str
            The decrypted token
        """
        return self.fernet.decrypt(token.encode()).decode()
