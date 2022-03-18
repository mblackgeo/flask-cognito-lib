import time
from typing import Callable, Optional

import requests
from jose import jwk, jwt
from jose.exceptions import JOSEError
from jose.utils import base64url_decode

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError


class TokenService:
    def __init__(self, cfg: Config, request_client: Optional[Callable] = None):
        self.cfg = cfg
        self.claims = None

        if not request_client:
            self.request_client = requests.get
        else:
            self.request_client = request_client

        self._load_jwk_keys()

    def _load_jwk_keys(self):
        try:
            response = self.request_client(self.cfg.jwk_endpoint)
            self.jwk_keys = response.json()["keys"]
        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e

    @staticmethod
    def _extract_headers(token):
        try:
            headers = jwt.get_unverified_headers(token)
            return headers
        except JOSEError as e:
            raise TokenVerifyError(str(e)) from e

    def _find_pkey(self, headers):
        kid = headers["kid"]
        for key in self.jwk_keys:
            if key["kid"] == kid:
                return key
        raise TokenVerifyError("Public key not found in jwks.json")

    @staticmethod
    def _verify_signature(token, pkey_data):
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
    def _extract_claims(token):
        try:
            claims = jwt.get_unverified_claims(token)
            return claims
        except JOSEError as e:
            raise TokenVerifyError(str(e)) from e

    @staticmethod
    def _check_expiration(claims, current_time):
        if not current_time:
            current_time = time.time()
        if current_time > claims["exp"]:
            raise TokenVerifyError("Token is expired")  # probably another exception

    def _check_audience(self, claims):
        # and the Audience  (use claims['client_id'] if verifying an access token)
        audience = claims["aud"] if "aud" in claims else claims["client_id"]
        if audience != self.cfg.user_pool_client_id:
            raise TokenVerifyError("Token was not issued for this audience")

    def _check_issuer(self, claims):
        # and the Issuer
        if claims["iss"] != self.cfg.issuer:
            raise TokenVerifyError("Token was not issuer is not correct")

    def verify(self, token, current_time=None):
        if not token:
            raise TokenVerifyError("No token provided")

        headers = self._extract_headers(token)
        pkey_data = self._find_pkey(headers)
        self._verify_signature(token, pkey_data)

        claims = self._extract_claims(token)
        self._check_expiration(claims, current_time)
        self._check_audience(claims)
        self._check_issuer(claims)

        self.claims = claims
