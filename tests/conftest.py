import pytest
from flask import Flask

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
    _app.config["AWS_COGNITO_USER_POOL_ID"] = "eu-west-1_Drvd8r4TM"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "545isk1een1lvilb9en643g3vd"
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


@pytest.fixture
def jwks():
    return {
        "keys": [
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "2hQZJREoWZ/3A7hEYG+iIa7GJD+Jweu1caQ4rFrh2JM=",
                "kty": "RSA",
                "n": "m_FrYse7laSfIvHgKHVJzRknFnEjad79b0hrqQ1FoNOZ_JX5_15lSnHy0gPM542ZZ_cjCe6tbEavz4dI3g0CxZRW6esjXzRefVAuphilpQ1gmQDjASa6Qg2LqUS1Hd04m9UGSJo9vdG1KRsOK-MXGaV5EglKaTcINcVs31-B5R53rjuwTEcWpMlYb9VRq86VUdGEzH4I74sa6NYo3dSftL9N0ghH2lq0I2l2taVCH7FUk3phOeksNyTQgxnWQ-pGYzqpZOcZmEEdQMT3fjd4_pcqXSYrB3lmSN0nXxorq1RGmkRRQ3d70-Veyh4KvU-f_VzIdwIc5yLOzf3RaHMvFw",
                "use": "sig",
            },
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "pv5k2Fdq+5uVgcb4jrgA76H7iVGvAO4uOmhpCheqTDo=",
                "kty": "RSA",
                "n": "pFToxHflSw-b8kfjaTERryoHdI4D1NaFCCNkNW1qaPSVp3FYZj4TzD3giF-XrnL0YgW_EpLs02mFWqHexgYfN-vJNOvbreT0wsmnzBoK2SlSKWqh70OBF26eVmmNCqMfRdNoP2QcqcagoKFRUkaxhC4TdVzPzb7l-xOnXrqsQlKCsR7ULuxYzBoRbSDJSq2YosE228Fq8ysMScle5i07fFUjpqnL3Yw1GQ3FPuBHYu5McAqLe1d_rRg2ER0FjVSggFut-3XICfe8Km8MCqglmnNT60RZo-ibsEXmN8zu2sJumyGLkGEDHJOf1VwKIdABWIey7UTlI2eYlqZRET04nw",
                "use": "sig",
            },
        ]
    }


@pytest.fixture
def cfg():
    return Config()


@pytest.fixture
def token_endpoint_request(mocker):
    response = mocker.Mock()
    response.json = mocker.Mock(return_value={"access_token": "test_access_token"})
    request = mocker.Mock(return_value=response)
    return request
