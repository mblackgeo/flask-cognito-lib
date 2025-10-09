import pytest
from flask import Flask
from pytest_mock import MockerFixture

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError


def test_plugin_init(cfg: Config) -> None:
    app = Flask(__name__)
    CognitoAuth(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_init_with_config_override(cfg_override: Config) -> None:
    app = Flask(__name__)
    CognitoAuth(app, cfg=cfg_override)
    assert (
        app.extensions[cfg_override.APP_EXTENSION_KEY].cfg.logout_redirect
        == cfg_override.logout_redirect
    )


def test_plugin_lazy_init(cfg: Config) -> None:
    app = Flask(__name__)
    CognitoAuth().init_app(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_lazy_init_with_config_override(cfg_override: Config) -> None:
    app = Flask(__name__)
    CognitoAuth().init_app(app, cfg=cfg_override)
    assert (
        app.extensions[cfg_override.APP_EXTENSION_KEY].cfg.logout_redirect
        == cfg_override.logout_redirect
    )


def test_plugin_get_tokens_parameters_state(app: Flask, cfg: Config) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf"}, expected_state="", code_verifier=""
        )


def test_plugin_get_tokens_parameters_code(app: Flask, cfg: Config) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"state": "asdf"}, expected_state="", code_verifier=""
        )


def test_plugin_get_tokens_state_invalid(app: Flask, cfg: Config) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf", "state": "qwer"},
            expected_state="1234",
            code_verifier="",
        )


def test_plugin_get_tokens(
    app: Flask,
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(json=lambda: {"access_token": "test_access_token"}),
    )
    tokens = cls.get_tokens(
        request_args={"code": "asdf", "state": "qwer"},
        expected_state="qwer",
        code_verifier="",
    )
    assert tokens.access_token == "test_access_token"


def test_plugin_exchange_refresh_token(
    app: Flask,
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
        return_value=mocker.Mock(
            json=lambda: {
                "access_token": "new_test_access_token",
                "refresh_token": "new_test_refresh_token",
            }
        ),
    )
    tokens = cls.exchange_refresh_token(
        refresh_token="test_refresh_token",
    )
    assert tokens.access_token == "new_test_access_token"
    assert tokens.refresh_token == "new_test_refresh_token"


def test_plugin_revoke_refresh_token(
    app: Flask,
    cfg: Config,
    mocker: MockerFixture,
) -> None:
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    mocker.patch(
        "requests.post",
    )

    cls.revoke_refresh_token(refresh_token="test_refresh_token")
