import time
from typing import Any, Callable, Dict, Optional

import requests
from jose import jwk, jwt
from jose.exceptions import JOSEError
from jose.utils import base64url_decode

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError


class TokenService:
    def __init__(self, cfg: Config, request_client: Optional[Callable] = None):
        self.cfg = cfg

        # Populate the claims after verification of the JWT
        self.claims: Dict[str, Any] = None

        if not request_client:
            self.request_client = requests.get
        else:
            self.request_client = request_client

        self._load_jwk_keys()

    def _load_jwk_keys(self):
        """Load the JWKs from the Cognito user pool endpoint JWK"""
        try:
            response = self.request_client(self.cfg.jwk_endpoint)
            self.jwk_keys = response.json()["keys"]

        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e

    @staticmethod
    def _extract_headers(token: str) -> Dict[str, Any]:
        """Extract the unverified headers from a JWT"""
        try:
            headers = jwt.get_unverified_headers(token)
            return headers
        except JOSEError as e:
            raise TokenVerifyError(str(e)) from e

    def _get_pkey(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        """Find the public key ID from JWT headers"""
        kid = headers["kid"]
        for key in self.jwk_keys:
            if key["kid"] == kid:
                return key

        raise TokenVerifyError("Public key not found in jwks.json")

    @staticmethod
    def _verify_signature(token: str, pkey_data: Dict[str, Any]) -> None:
        """Verify that signature of the JWT given the public key"""

        try:
            # construct the public key
            public_key = jwk.construct(pkey_data)
        except JOSEError as e:
            raise TokenVerifyError(str(e)) from e

        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit(".", 1)

        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        # verify the signature
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            raise TokenVerifyError("Signature verification failed")

    @staticmethod
    def _extract_claims(token: str) -> Dict[str, Any]:
        """Extract the claims from a JWT"""
        try:
            claims = jwt.get_unverified_claims(token)
            return claims
        except JOSEError as e:
            raise TokenVerifyError(str(e)) from e

    @staticmethod
    def _check_expiration(
        claims: Dict[str, Any], current_time: Optional[float] = None
    ) -> None:
        """Check if a JWT has expired"""
        if current_time is None:
            current_time = time.time()

        if current_time > claims["exp"]:
            raise TokenVerifyError("Token is expired")  # probably another exception

    def _check_audience(self, claims: Dict[str, Any]) -> None:
        """Check if the JWT was issued for the correct audience"""
        audience = claims["aud"] if "aud" in claims else claims["client_id"]
        if audience != self.cfg.user_pool_client_id:
            raise TokenVerifyError("Token was not issued for this audience")

    def _check_issued_at(
        self, claims: Dict[str, Any], current_time: Optional[float] = None
    ) -> None:
        """Check if the JWT was issued by the correct issuer"""
        if current_time is None:
            current_time = time.time()

        min_time = current_time - (5 * 60)
        max_time = current_time + (5 * 60)

        if claims["iat"] > max_time or claims["iat"] < min_time:
            raise TokenVerifyError("Token issued at time is out of range")

    def _check_issuer(self, claims: Dict[str, Any]) -> None:
        """Check if the JWT was issued by the correct issuer"""
        if claims["iss"] != self.cfg.issuer:
            raise TokenVerifyError("Token was not issuer is not correct")

    def _check_nonce(self, claims: Dict[str, Any], nonce: Optional[str] = None) -> None:
        """Check if the JWT nonce value is correct"""

        # TODO this is the ID token, need to check that separately
        if nonce:
            try:
                claimed_nonce = claims["nonce"]
            except KeyError as e:
                raise TokenVerifyError("Token nonce is not present") from e

            if claimed_nonce != nonce:
                raise TokenVerifyError("Token nonce is not correct")

    def verify(
        self,
        token: str,
        nonce: Optional[str] = None,
        current_time: Optional[int] = None,
    ) -> None:
        """Verify the content and signature of a JWT from Cognito

        This will check the audience, issuer, expiry and validate the sigature
        of the JWT matches the public keys from the user pool

        Parameters
        ----------
        token : str
            The encoded JWT
        nonce : Optional[str]
            The nonce value used when the token was requested. Used to prevent
            replay attacks.
        current_time : Optional[int], optional
            Pass a unix time , by default None

        Raises
        ------
        TokenVerifyError
            If not token is passed, or any checks fail
        """
        if not token:
            raise TokenVerifyError("No token provided")

        headers = self._extract_headers(token)
        pkey_data = self._get_pkey(headers)
        self._verify_signature(token, pkey_data)

        claims = self._extract_claims(token)
        self._check_expiration(claims, current_time)
        self._check_issued_at(claims, current_time)
        self._check_audience(claims)
        self._check_issuer(claims)
        self._check_nonce(claims, nonce)

        self.claims = claims
