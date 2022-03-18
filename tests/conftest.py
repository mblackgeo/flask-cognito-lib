import pytest
from flask import Flask

from flask_cognito_lib import CognitoAuth


@pytest.fixture(autouse=True)
def app():
    """Create application for the tests."""

    _app = Flask(__name__)
    CognitoAuth(_app)

    ctx = _app.test_request_context()
    ctx.push()

    _app.config["TESTING"] = True
    _app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False

    # minimum require configuration for CognitoAuth extension
    _app.config["AWS_COGNITO_USER_POOL_ID"] = "eu-west-1_123456"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "random-client-id"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "secure-client-secret"
    _app.config["AWS_COGNITO_REDIRECT_URL"] = "http://example.com/redirect"
    _app.config["AWS_COGNITO_DOMAIN"] = "http://auth.example.com"
    _app.config["AWS_REGION"] = "eu-west-1"

    _app.testing = True

    yield _app
    ctx.pop()


@pytest.fixture
def client():
    cl = app.test_client()
    yield cl
