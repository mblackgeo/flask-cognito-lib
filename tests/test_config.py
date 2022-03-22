import pytest

from flask_cognito_lib.exceptions import ConfigurationError


def test_missing_config(app, cfg):
    """No configuration has been set, should throw an error"""
    with pytest.raises(ConfigurationError):
        # remove a required configuration parameter
        app.config.pop("AWS_REGION")
        print(cfg.region)


def test_issuer(cfg):
    """Check if forms the issuer URL correctly"""
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_c7O90SNDF"
    assert cfg.issuer == expected
