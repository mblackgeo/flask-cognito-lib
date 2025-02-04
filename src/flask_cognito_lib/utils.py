import re
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from os import urandom
from typing import Literal, Optional, Union


def secure_random(n_bytes: int = 32) -> str:
    """Generate a secure URL-safe random string"""
    return urlsafe_b64encode(urandom(n_bytes)).decode("utf-8")


def generate_code_verifier(n_bytes: int = 32) -> str:
    """Create a code verification secret"""
    code_verifier = secure_random(n_bytes=n_bytes)
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    return code_verifier


def generate_code_challenge(code_verifier: str) -> str:
    """Create a code challenge (SHA256) from a code verifier"""
    code_challenge = sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = urlsafe_b64encode(code_challenge).decode("utf-8")
    return code_challenge.replace("=", "")


@dataclass
class CognitoTokenResponse:
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CognitoExtraAuthorizeParams:
    """
    Extra parameters that can be passed to the Cognito hosted UI
    https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
    """

    identity_provider: Optional[
        Union[
            Literal[
                "Facebook", "Google", "LoginWithAmazon", "SignInWithApple", "COGNITO"
            ],
            str,
        ]
    ] = None

    idp_identifier: Optional[str] = None

    # https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managed-login.html#managed-login-localization
    lang: Optional[
        Literal["de", "en", "es", "fr", "id", "it", "ko", "pt-BR", "zh-CN", "zh-TW"]
    ] = None

    login_hint: Optional[str] = None
