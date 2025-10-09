import re

import pytest
import requests
from flask import Flask
from pytest_mock import MockerFixture
from requests import JSONDecodeError

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError
from flask_cognito_lib.services.cognito_svc import CognitoService


def raise_exception(e: Exception) -> None:
    raise e


def test_base_url(cfg: Config) -> None:
    cognito = CognitoService(cfg)
    assert cognito.cfg.domain == "https://webapp-test.auth.eu-west-1.amazoncognito.com"


def test_sign_in_url(cfg: Config) -> None:
    cognito = CognitoService(cfg)
    res = cognito.get_sign_in_url(
        code_challenge="asdf",
        state="1234",
        nonce="6789",
        scopes=["openid", "profile"],
    )
    assert res == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
        "?response_type=code"
        "&client_id=4lln66726pp3f4gi1krj0sta9h"
        "&redirect_uri=http%3A//localhost%3A5000/postlogin"
        "&state=1234"
        "&nonce=6789"
        "&code_challenge=asdf"
        "&code_challenge_method=S256"
        "&scope=openid+profile"
    )


def test_exchange_code_for_token_requests_error(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        side_effect=requests.exceptions.RequestException("404"),
    )

    with pytest.raises(CognitoError):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")


def test_exchange_code_for_token(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )

    cognito = CognitoService(cfg)
    token = cognito.exchange_code_for_token(code="test_code", code_verifier="asdf")
    assert token.access_token == "test_access_token"


def test_exchange_code_for_token_with_public_client(
    app: Flask,
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )

    app.config.pop("AWS_COGNITO_USER_POOL_CLIENT_SECRET")

    cognito = CognitoService(cfg)
    token = cognito.exchange_code_for_token(code="test_code", code_verifier="asdf")
    assert token.access_token == "test_access_token"


def test_exchange_code_for_token_error(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    error_code = "some error code"
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "error": error_code,
            }
        ),
    )

    with pytest.raises(
        CognitoError,
        match=f"CognitoError: {error_code}",
    ):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")


def test_exchange_code_for_token_error_description(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    error_code = "some error code"
    error_description = "some error description"
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "error": error_code,
                "error_description": error_description,
            }
        ),
    )

    with pytest.raises(
        CognitoError,
        match=f"CognitoError: {error_code} - {error_description}",
    ):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")


def test_exchange_code_for_token_error_json(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: raise_exception(JSONDecodeError("Expecting value", "", 0))
        ),
    )

    with pytest.raises(
        CognitoError,
        match=re.escape("Expecting value: line 1 column 1 (char 0)"),
    ):
        cognito = CognitoService(cfg)
        cognito.exchange_code_for_token(code="", code_verifier="")


def test_refresh_token(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "access_token": "new_test_access_token",
                "refresh_token": "new_test_refresh_token",
            }
        ),
    )

    cognito = CognitoService(cfg)
    token = cognito.exchange_refresh_token(refresh_token="test_refresh_token")

    assert token.access_token == "new_test_access_token"
    assert token.refresh_token == "new_test_refresh_token"


def test_refresh_token_typo(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    # Check the function works under the old name that had a typo
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "access_token": "new_test_access_token",
                "refresh_token": "new_test_refresh_token",
            }
        ),
    )

    cognito = CognitoService(cfg)
    token = cognito.exhange_refresh_token(refresh_token="test_refresh_token")

    assert token.access_token == "new_test_access_token"
    assert token.refresh_token == "new_test_refresh_token"


def test_revoke_refresh_token(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
    )

    cognito = CognitoService(cfg)
    cognito.revoke_refresh_token(refresh_token="test_refresh_token")


def test_revoke_refresh_token_error_json(
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: raise_exception(JSONDecodeError("Expecting value", "", 0))
        ),
    )

    # Non-JSON response should not raise an exception
    cognito = CognitoService(cfg)
    cognito.revoke_refresh_token(refresh_token="test_refresh_token")
