import pytest

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoConfigurationError


def test_missing_config(app):
    """No configuration has been set, should throw an error"""
    with pytest.raises(CognitoConfigurationError):
        # remove a required configuration parameter
        app.config.pop("AWS_REGION")
        cfg = Config()
        print(cfg.region)


def test_issuer():
    """Check if forms the issuer URL correctly"""
    cfg = Config()
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_123456"
    assert cfg.issuer == expected
