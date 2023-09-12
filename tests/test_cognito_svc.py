import pytest
import requests

from flask_cognito_lib.exceptions import CognitoError
from flask_cognito_lib.services.cognito_svc import CognitoService


def test_base_url(cfg):
    cognito = CognitoService(cfg)
    assert (
        cognito.cfg.domain == "https://flask-cog-test.auth.us-east-1.amazoncognito.com"
    )


def test_sign_in_url(cfg):
    cognito = CognitoService(cfg)
    res = cognito.get_sign_in_url(
        code_challenge="asdf",
        state="1234",
        nonce="6789",
        scopes=["openid", "profile"],
    )
    assert res == (
        "https://flask-cog-test.auth.us-east-1.amazoncognito.com/oauth2/authorize"
        "?response_type=code"
        "&client_id=7og7do7m7tq0gi7ujm2uloa99v"
        "&redirect_uri=http%3A//localhost%3A5000/postlogin"
        "&state=1234"
        "&nonce=6789"
        "&code_challenge=asdf"
        "&code_challenge_method=S256"
        "&scope=openid+profile"
    )


def test_exchange_code_for_token_requests_error(cfg, mocker):
    mocker.patch(
        "requests.post",
        side_effect=requests.exceptions.RequestException("404"),
    )

    with pytest.raises(CognitoError):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")


def test_exchange_code_for_token(cfg, mocker):
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )

    cognito = CognitoService(cfg)
    token = cognito.exchange_code_for_token(code="test_code", code_verifier="asdf")
    assert token.access_token == "test_access_token"


def test_exchange_code_for_token_with_public_client(app, cfg, mocker):
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )

    app.config.pop("AWS_COGNITO_USER_POOL_CLIENT_SECRET")

    cognito = CognitoService(cfg)
    token = cognito.exchange_code_for_token(code="test_code", code_verifier="asdf")
    assert token.access_token == "test_access_token"


def test_exchange_code_for_token_error(cfg, mocker):
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"error": "some error code"}),
    )

    with pytest.raises(CognitoError):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")
