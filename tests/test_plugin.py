import pytest
from flask import Flask

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.exceptions import CognitoError


def test_plugin_init(cfg):
    app = Flask(__name__)
    CognitoAuth(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_lazy_init(cfg):
    app = Flask(__name__)
    CognitoAuth().init_app(app)
    assert cfg.APP_EXTENSION_KEY in app.extensions


def test_plugin_get_tokens_parameters_missing(app, cfg):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf"}, expected_state="", code_verifier=""
        )
        cls.get_tokens(
            request_args={"state": "asdf"}, expected_state="", code_verifier=""
        )


def test_plugin_get_tokens_state_invalid(app, cfg):
    cls = app.extensions[cfg.APP_EXTENSION_KEY]
    with pytest.raises(CognitoError):
        cls.get_tokens(
            request_args={"code": "asdf", "state": "qwer"},
            expected_state="1234",
            code_verifier="",
        )


def test_plugin_get_tokens(app, cfg, mocker):
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
