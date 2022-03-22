import pytest
from flask import Flask
from jwt import PyJWKSet

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.config import Config


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
    _app.config["AWS_COGNITO_USER_POOL_ID"] = "eu-west-1_c7O90SNDF"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "4lln66726pp3f4gi1krj0sta9h"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "secure-client-secret"
    _app.config["AWS_COGNITO_REDIRECT_URL"] = "http://localhost:5000/postlogin"
    _app.config["AWS_COGNITO_LOGOUT_URL"] = "http://localhost:5000/postlogout"
    _app.config[
        "AWS_COGNITO_DOMAIN"
    ] = "https://webapp-test.auth.eu-west-1.amazoncognito.com"
    _app.config["AWS_REGION"] = "eu-west-1"

    _app.testing = True

    yield _app
    ctx.pop()


@pytest.fixture
def client():
    cl = app.test_client()
    yield cl


@pytest.fixture
def jwks():
    return {
        "keys": [
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "spvUVat6clXStpoIh6nCUttT6y6AmPoPAty+UMNvQ2Y=",
                "kty": "RSA",
                "n": "0u3EqunReyXWvYL-TIL41mpybOLQZMkzayIMXrGdw6AjDD0bI_vWo-s4j4Xpw9fqV4XMyfo-q7EB_XfMlTSIDqbYt0PIqw3ULUS2utC5QZrpUsEmcws1RGW1Ed-sZjmhozrFcugywVC7NMFb3zQGmOnLcElsfzAIZOfGQ4KPsLTxpUG8OoxU3wzoqSj00YydMAw-6-KEhv7RQbE5ik82gdSu5vzrB1n8iE4xJtwt7BNA1G3jR6cIATSDubb_mqrN7ZGr_d8_AF4LjscNVT28ois7XQpzY21jsPYftRmrUHitoULzoc_DngPNlG1HFPfU_-RIAq0v_LMgd3qMIEWHaw",
                "use": "sig",
            },
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "2gH42FHBLdfSv1YQwmql6bi45sX3dovsvvuCXQQ6Uaw=",
                "kty": "RSA",
                "n": "xaEhQcrn4hEXvAy5iCSTy0Tt_6MlvEk00k8eiJkRN8t-2YRZrU1-DK9FNY2tm9YxwFV1ynPSkkHkUPY3CWQt_zInhc8bx8ZjtzwqdApbkU_2A00LcUd_8VzmfGOToQ80EvTZ5QZvxQQxqcoOopX0WnysqFQT413isUaC4WTQcxb0nC78UZFW0t__xFuwtti-cwvWSUWdv_tLFBqBvhlvohENoCAQrXGsK64QCAj4dsagk2dsmrgdiOyihwnW4zx3Dcu4hDQMEcbMm4b76UN4_084k4rEpwcoDjq9wBx9QVUt9Xt81C2OWBkBz4UDX0QtAvTvl_RzErVDEwFtCEVfDQ",
                "use": "sig",
            },
        ]
    }


@pytest.fixture
def cfg():
    return Config()


@pytest.fixture(autouse=True)
def jwk_patch(mocker, jwks):
    mocker.patch(
        "jwt.jwks_client.PyJWKClient.get_jwk_set",
        return_value=PyJWKSet.from_dict(jwks),
    )
