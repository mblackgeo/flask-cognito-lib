import pytest
from flask import Flask

from flask_cognito_lib.config import Config, get
from flask_cognito_lib.exceptions import ConfigurationError


def test_get_default() -> None:
    res = get("ASDF", required=False, default=1)
    assert res == 1


def test_missing_config(app: Flask, cfg: Config) -> None:
    """No configuration has been set, should throw an error"""
    with pytest.raises(ConfigurationError):
        # remove a required configuration parameter
        app.config.pop("AWS_REGION")
        print(cfg.region)


def test_disabled(cfg: Config) -> None:
    """Check if extension is enabled (by default it should be)"""
    assert not cfg.disabled


def test_issuer(cfg: Config) -> None:
    """Check if forms the issuer URL correctly"""
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF"
    assert cfg.issuer == expected


def test_client_secret(cfg: Config) -> None:
    assert cfg.user_pool_client_secret == "secure-client-secret"


def test_logout_url(cfg: Config) -> None:
    assert cfg.logout_redirect == "http://localhost:5000/postlogout"


def test_cookie_age(cfg: Config) -> None:
    assert cfg.max_cookie_age_seconds == 1e9


def test_token_endpoint(cfg: Config) -> None:
    assert cfg.token_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/token"
    )


def test_logout_endpoint(cfg: Config) -> None:
    assert cfg.logout_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/logout"
        "?client_id=4lln66726pp3f4gi1krj0sta9h"
        "&logout_uri=http%3A//localhost%3A5000/postlogout"
    )


def test_user_info_endpoint(cfg: Config) -> None:
    assert cfg.user_info_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/userInfo"
    )


def test_revoke_endpoint(cfg: Config) -> None:
    assert cfg.revoke_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/revoke"
    )


def test_secret_key(app: Flask, cfg: Config) -> None:
    app.config["SECRET_KEY"] = "very-secure"
    assert cfg.secret_key == b"very-secure"

    app.config["SECRET_KEY"] = b"very-secure"
    assert cfg.secret_key == b"very-secure"
