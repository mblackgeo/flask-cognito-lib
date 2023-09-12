import pytest

from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError
from flask_cognito_lib.services.token_svc import TokenService


def test_verify_no_access_token(cfg):
    serv = TokenService(cfg=cfg)
    with pytest.raises(TokenVerifyError):
        serv.verify_access_token(None)


def test_verify_no_id_token(cfg):
    serv = TokenService(cfg=cfg)
    with pytest.raises(TokenVerifyError):
        serv.verify_id_token(None)


def test_get_public_key(cfg):
    with pytest.raises(CognitoError):
        # Using a dummy token should not find matching key
        TokenService(cfg).get_public_key(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
            ".dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"
        )


def test_verify_access_token(cfg, access_token):
    serv = TokenService(cfg=cfg)
    claims = serv.verify_access_token(access_token, leeway=1e9)
    assert claims == {
        "auth_time": 1694490743,
        "client_id": "7og7do7m7tq0gi7ujm2uloa99v",
        "cognito:groups": ["admin"],
        "exp": 1694494343,
        "iat": 1694490743,
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_HC5viybYt",
        "jti": "4ac5f32c-29a6-4181-a570-bf52d03e8b05",
        "origin_jti": "6d58f82c-86de-4415-8196-a2b3dcc17079",
        "scope": "phone openid email",
        "sub": "49971d1a-f720-432c-abbc-9d466f260d98",
        "token_use": "access",
        "username": "49971d1a-f720-432c-abbc-9d466f260d98",
        "version": 2,
    }


def test_verify_additional_access_token(cfg, additional_access_token):
    serv = TokenService(cfg=cfg)
    claims = serv.verify_access_token(additional_access_token, leeway=1e9)
    assert claims == {
        "auth_time": 1694298448,
        "client_id": "j7hha0k2v15pkkj7f8srkldud",
        "event_id": "61096a43-b05d-40a1-bd97-a3701f429f8e",
        "exp": 1694302048,
        "iat": 1694298448,
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_HC5viybYt",
        "jti": "bb5c5f91-c1fe-4705-afda-f608af318228",
        "origin_jti": "a828a523-77ba-46a4-baed-dcf729eb8ecc",
        "scope": "phone openid email",
        "sub": "49971d1a-f720-432c-abbc-9d466f260d98",
        "token_use": "access",
        "username": "49971d1a-f720-432c-abbc-9d466f260d98",
        "version": 2,
    }


def test_verify_id_token(cfg, id_token):
    serv = TokenService(cfg=cfg)
    claims = serv.verify_id_token(id_token, leeway=1e9)
    assert claims == {
        "at_hash": "8DLjfTWSvQuFfeDonQaT4w",
        "aud": "7og7do7m7tq0gi7ujm2uloa99v",
        "auth_time": 1694490743,
        "cognito:groups": ["admin"],
        "cognito:username": "49971d1a-f720-432c-abbc-9d466f260d98",
        "email": "test@flaskcognito.com",
        "email_verified": True,
        "exp": 1694494343,
        "iat": 1694490743,
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_HC5viybYt",
        "jti": "dd710d8e-cbe0-4b98-9c7c-aacff59e8a8c",
        "nonce": "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A=",
        "origin_jti": "6d58f82c-86de-4415-8196-a2b3dcc17079",
        "sub": "49971d1a-f720-432c-abbc-9d466f260d98",
        "token_use": "id",
    }


def test_verify_additional_id_token(cfg, additional_id_token):
    serv = TokenService(cfg=cfg)
    claims = serv.verify_id_token(additional_id_token, leeway=1e9)
    assert claims == {
        "at_hash": "2CzhktXsmHGpFTDd5XOrbA",
        "aud": "j7hha0k2v15pkkj7f8srkldud",
        "auth_time": 1694298448,
        "cognito:username": "49971d1a-f720-432c-abbc-9d466f260d98",
        "email": "test@flaskcognito.com",
        "email_verified": True,
        "event_id": "61096a43-b05d-40a1-bd97-a3701f429f8e",
        "exp": 1694302048,
        "iat": 1694298448,
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_HC5viybYt",
        "jti": "16319665-0107-40fe-bb61-3a0c81ca1269",
        "origin_jti": "a828a523-77ba-46a4-baed-dcf729eb8ecc",
        "sub": "49971d1a-f720-432c-abbc-9d466f260d98",
        "token_use": "id",
    }


def test_verify_access_token_invalid_client(app, cfg, access_token):
    app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "wrong"
    with pytest.raises(TokenVerifyError):
        serv = TokenService(cfg=cfg)
        serv.verify_access_token(access_token, leeway=1e9)
