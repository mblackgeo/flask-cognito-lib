import pytest

from flask_cognito_lib.config import get
from flask_cognito_lib.exceptions import ConfigurationError


def test_get_default():
    res = get("ASDF", required=False, default=1)
    assert res == 1


def test_missing_config(app, cfg):
    """No configuration has been set, should throw an error"""
    with pytest.raises(ConfigurationError):
        # remove a required configuration parameter
        app.config.pop("AWS_REGION")
        print(cfg.region)


def test_disabled(cfg):
    """Check if extension is enabled (by default it should be)"""
    assert not cfg.disabled


def test_issuer(cfg):
    """Check if forms the issuer URL correctly"""
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF"
    assert cfg.issuer == expected


def test_client_secret(cfg):
    assert cfg.user_pool_client_secret == "secure-client-secret"


def test_logout_url(cfg):
    assert cfg.logout_redirect == "http://localhost:5000/postlogout"


def test_cookie_age(cfg):
    assert cfg.max_cookie_age_seconds == 1e9


def test_token_endpoint(cfg):
    assert cfg.token_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/token"
    )


def test_logout_endpoint(cfg):
    assert cfg.logout_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/logout"
        "?client_id=4lln66726pp3f4gi1krj0sta9h"
        "&logout_uri=http%3A//localhost%3A5000/postlogout"
    )


def test_user_info_endpoint(cfg):
    assert cfg.user_info_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/userInfo"
    )


def test_revoke_endpoint(cfg):
    assert cfg.revoke_endpoint == (
        "https://webapp-test.auth.eu-west-1.amazoncognito.com/oauth2/revoke"
    )
