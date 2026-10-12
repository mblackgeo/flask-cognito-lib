import time
import warnings
from types import SimpleNamespace
from typing import Any, Dict

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask
from pytest_mock import MockerFixture

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError
from flask_cognito_lib.services.token_svc import TokenService


def test_verify_no_access_token(cfg: Config) -> None:
    serv = TokenService(cfg=cfg)
    with pytest.raises(TokenVerifyError):
        serv.verify_access_token("")


def test_verify_no_id_token(cfg: Config) -> None:
    serv = TokenService(cfg=cfg)
    with pytest.raises(TokenVerifyError):
        serv.verify_id_token("")


def test_get_public_key(cfg: Config) -> None:
    with pytest.raises(CognitoError):
        # Using a dummy token should not find matching key
        TokenService(cfg).get_public_key(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
            ".dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"
        )


def test_verify_access_token(cfg: Config, access_token: str) -> None:
    serv = TokenService(cfg=cfg)
    claims = serv.verify_access_token(access_token, leeway=1e9)
    assert claims == {
        "sub": "9048d38f-8174-49b9-8d59-3238172823d8",
        "cognito:groups": ["admin"],
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF",
        "version": 2,
        "client_id": "4lln66726pp3f4gi1krj0sta9h",
        "origin_jti": "d4811bf1-2798-4d33-b65c-2f8254729dd2",
        "event_id": "18828d18-b465-470e-84b6-17520ded299b",
        "token_use": "access",
        "scope": "phone openid email",
        "auth_time": 1647961493,
        "exp": 1647965093,
        "iat": 1647961493,
        "jti": "0fe29a9e-6e94-479b-987b-e45696d5843a",
        "username": "mblack",
    }


def test_verify_id_token(cfg: Config, id_token: str) -> None:
    serv = TokenService(cfg=cfg)
    claims = serv.verify_id_token(id_token, leeway=1e9)
    assert claims == {
        "at_hash": "WqTgBN7uFPnnJRgyd86WLA",
        "sub": "9048d38f-8174-49b9-8d59-3238172823d8",
        "cognito:groups": ["admin"],
        "email_verified": False,
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF",
        "cognito:username": "mblack",
        "nonce": "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A=",
        "origin_jti": "d4811bf1-2798-4d33-b65c-2f8254729dd2",
        "aud": "4lln66726pp3f4gi1krj0sta9h",
        "event_id": "18828d18-b465-470e-84b6-17520ded299b",
        "token_use": "id",
        "auth_time": 1647961493,
        "exp": 1647965093,
        "iat": 1647961493,
        "jti": "054b8e66-5853-4127-9d55-e3a29dbd84bd",
        "email": "mblack@sparkgeo.com",
    }


def test_verify_access_token_invalid_client(
    app: Flask,
    cfg: Config,
    access_token: str,
) -> None:
    app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "wrong"
    with pytest.raises(TokenVerifyError):
        serv = TokenService(cfg=cfg)
        serv.verify_access_token(access_token, leeway=1e9)


def test_encrypt_token(app: Flask, cfg: Config, refresh_token: str) -> None:
    serv = TokenService(cfg=cfg)
    encrypted_token = serv.encrypt_token(refresh_token)
    assert encrypted_token != refresh_token
    assert serv.decrypt_token(encrypted_token) == refresh_token


def test_decrypt_token_error(app: Flask, cfg: Config, refresh_token: str) -> None:
    with pytest.raises(CognitoError, match="Error decrypting token"):
        serv = TokenService(cfg=cfg)
        serv.decrypt_token(refresh_token)


def test_verify_tokens_no_pyjwt_deprecation_warning(
    cfg: Config, access_token: str, id_token: str
) -> None:
    serv = TokenService(cfg=cfg)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        serv.verify_access_token(access_token, leeway=1e9)
        serv.verify_id_token(id_token, leeway=1e9)


def _sign_and_patch(
    mocker: MockerFixture, serv: TokenService, claims: Dict[str, Any]
) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mocker.patch.object(
        serv, "get_public_key", return_value=SimpleNamespace(key=key.public_key())
    )
    return jwt.encode(claims, key, algorithm="RS256")


@pytest.mark.parametrize("missing", ["client_id", "iss", "exp", "iat"])
def test_verify_access_token_missing_required_claim(
    mocker: MockerFixture, cfg: Config, missing: str
) -> None:
    serv = TokenService(cfg=cfg)
    now = int(time.time())
    claims = {
        "client_id": cfg.user_pool_client_id,
        "iss": cfg.issuer,
        "exp": now + 60,
        "iat": now,
    }
    del claims[missing]
    token = _sign_and_patch(mocker, serv, claims)
    with pytest.raises(TokenVerifyError):
        serv.verify_access_token(token)


@pytest.mark.parametrize("missing", ["aud", "iss", "exp", "iat"])
def test_verify_id_token_missing_required_claim(
    mocker: MockerFixture, cfg: Config, missing: str
) -> None:
    serv = TokenService(cfg=cfg)
    now = int(time.time())
    claims = {
        "aud": cfg.user_pool_client_id,
        "iss": cfg.issuer,
        "exp": now + 60,
        "iat": now,
    }
    del claims[missing]
    token = _sign_and_patch(mocker, serv, claims)
    with pytest.raises(TokenVerifyError):
        serv.verify_id_token(token)
