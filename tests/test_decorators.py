import pytest
from flask import session

from flask_cognito_lib.decorators import remove_from_session
from flask_cognito_lib.exceptions import TokenVerifyError


def test_remove_from_session(client):
    with client as c:
        with c.session_transaction() as sess:
            sess["a"] = 123

        remove_from_session("a")
        assert "a" not in session

        # no-op for non-existant keys
        remove_from_session("b")


def test_cognito_login(client, cfg):
    response = client.get("/login")

    # should 302 redirect to coginto
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.authorize_endpoint)


def test_cognito_login_callback_expired(app, client):
    # Set Cognito response to small value so that tokens have expired
    app.config.AWS_COGNITO_RESPONSE_LEEWAY = 0

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A"

    with pytest.raises(TokenVerifyError):
        client.get("/postlogin")


def test_cognito_login_callback_invalid_nonce(client):
    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "wrong"

    with pytest.raises(TokenVerifyError):
        client.get("/postlogin")


def test_cognito_login_callback(client, cfg, access_token):
    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A="

        # returns OK and sets the cookie
        response = client.get("/postlogin")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"
        assert response.headers["Set-Cookie"].startswith(
            f"{cfg.COOKIE_NAME}={access_token}"
        )

        # removes one-time use codes from the session
        assert "code_verifier" not in session
        assert "nonce" not in session

        # check that user claims and user info are stored in the session
        assert "claims" in session
        assert "user_info" in session
