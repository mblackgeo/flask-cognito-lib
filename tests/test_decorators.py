import pytest
from flask import session

from flask_cognito_lib.decorators import remove_from_session
from flask_cognito_lib.exceptions import TokenVerifyError


def test_remove_from_session(client):
    with client.session_transaction() as sess:
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


def test_cognito_custom_state(client, cfg):
    with client.session_transaction() as sess:
        sess["state"] = "homepage"

    response = client.get("/login")

    # should 302 redirect to coginto
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.authorize_endpoint)
    assert "__homepage&" in response.headers["location"]


def test_cognito_custom_scopes(client, app, cfg):
    app.config["AWS_COGNITO_SCOPES"] = ["openid", "profile", "phone", "email"]
    response = client.get("/login")

    # should 302 redirect to coginto
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.authorize_endpoint)
    assert "scope=openid+profile+phone+email" in response.headers["location"]


def test_cognito_login_callback_expired(app, client, token_response):
    # Set Cognito response to small value so that tokens have expired
    app.config.AWS_COGNITO_RESPONSE_LEEWAY = 0

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A"

    with pytest.raises(TokenVerifyError):
        client.get("/postlogin")


def test_cognito_login_callback_invalid_nonce(client, token_response):
    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "wrong"

    with pytest.raises(TokenVerifyError):
        client.get("/postlogin")


def test_cognito_login_callback(client, cfg, access_token, token_response):
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


def test_cognito_logout(client, cfg):
    # should 302 redirect to coginto
    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.logout_endpoint)


def test_auth_required_expired_token(client, cfg, app, access_token):
    # 403 if the token verification has failed
    app.config["AWS_COGNITO_EXPIRATION_LEEWAY"] = 0
    client.set_cookie(server_name="localhost", key=cfg.COOKIE_NAME, value=access_token)
    response = client.get("/private")
    assert response.status_code == 403


def test_auth_required_valid_token(client_with_cookie):
    # 200 if the token passes verification
    response = client_with_cookie.get("/private")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_groups_valid(client_with_cookie):
    # Has access to this route as the token has the correct group membership
    response = client_with_cookie.get("/valid_group")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_groups_invalid(client_with_cookie):
    # 403 as the token isn't in this group
    response = client_with_cookie.get("/invalid_group")
    assert response.status_code == 403
