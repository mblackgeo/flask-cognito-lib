from base64 import urlsafe_b64encode
from hashlib import sha256

import pytest
from cryptography.fernet import Fernet
from flask import session

from flask_cognito_lib.decorators import get_token_from_cookie, remove_from_session
from flask_cognito_lib.exceptions import CognitoError, TokenVerifyError


def test_remove_from_session(client):
    with client.session_transaction() as sess:
        sess["a"] = 123

    remove_from_session("a")
    assert "a" not in session

    # no-op for non-existant keys
    remove_from_session("b")


def test_get_token_from_cookie(mocker):
    # Test when token is None
    mocker.patch(
        "flask_cognito_lib.decorators.request.cookies.get",
        return_value=None,
    )
    assert get_token_from_cookie("cookie_name") is None

    # Test when token is not None and cookie_name is not COOKIE_NAME_REFRESH
    mocker.patch(
        "flask_cognito_lib.decorators.request.cookies.get",
        return_value="token",
    )
    assert get_token_from_cookie("cookie_name") == "token"


def test_get_token_from_cookie_refresh(
    client_with_cookie_refresh, mocker, cfg, refresh_token
):
    with client_with_cookie_refresh:
        mocker.patch(
            "flask_cognito_lib.decorators.request.cookies.get",
            return_value=refresh_token,
        )

        assert get_token_from_cookie(cfg.COOKIE_NAME_REFRESH) == refresh_token


def test_get_token_from_cookie_refresh_encrypted(
    client_with_cookie_refresh_encrypted,
    mocker,
    cfg,
    refresh_token,
    refresh_token_encrypted,
):
    with client_with_cookie_refresh_encrypted:
        mocker.patch(
            "flask_cognito_lib.decorators.request.cookies.get",
            return_value=refresh_token_encrypted,
        )
        assert get_token_from_cookie(cfg.COOKIE_NAME_REFRESH) == refresh_token


def test_cognito_login(client, cfg):
    response = client.get("/login")

    # should 302 redirect to cognito
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.authorize_endpoint)


def test_cognito_custom_state(client, cfg):
    with client.session_transaction() as sess:
        sess["state"] = "homepage"

    response = client.get("/login")

    # should 302 redirect to cognito
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.authorize_endpoint)
    assert "__homepage&" in response.headers["location"]


def test_cognito_custom_scopes(client, app, cfg):
    app.config["AWS_COGNITO_SCOPES"] = ["openid", "profile", "phone", "email"]
    response = client.get("/login")

    # should 302 redirect to cognito
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

        # check that access token is set in the cookie but not the refresh token
        cookies_set = response.headers.getlist("Set-Cookie")
        assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}={access_token}")
        assert cfg.COOKIE_NAME_REFRESH not in response.headers["Set-Cookie"]

        # removes one-time use codes from the session
        assert "code_verifier" not in session
        assert "nonce" not in session

        # check that user claims and user info are stored in the session
        assert "claims" in session
        assert "user_info" in session


def test_cognito_login_callback_refresh(
    client,
    cfg,
    access_token,
    refresh_token,
    token_response,
):
    client.application.config["AWS_COGNITO_REFRESH_FLOW_ENABLED"] = True
    client.application.config["AWS_COGNITO_REFRESH_COOKIE_ENCRYPTED"] = False

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A="

        # returns OK and sets the cookie
        response = c.get("/postlogin")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that both access and refresh token is set in the cookie
        cookies_set = response.headers.getlist("Set-Cookie")
        assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}={access_token}")
        assert cookies_set[1].startswith(f"{cfg.COOKIE_NAME_REFRESH}={refresh_token}")


def test_cognito_login_callback_refresh_encrypted(
    client,
    cfg,
    access_token,
    refresh_token,
    token_response,
):
    client.application.config["AWS_COGNITO_REFRESH_FLOW_ENABLED"] = True
    client.application.config["AWS_COGNITO_REFRESH_COOKIE_ENCRYPTED"] = True

    fernet = Fernet(
        urlsafe_b64encode(sha256(cfg.secret_key.encode()).digest()),
    )

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A="

        # returns OK and sets the cookie
        response = c.get("/postlogin")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that both access and refresh token is set in the cookie
        cookies_set = response.headers.getlist("Set-Cookie")
        assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}={access_token}")
        assert cookies_set[1].startswith(f"{cfg.COOKIE_NAME_REFRESH}=")

        # check that the refresh token can be decrypted using Fernet and matches the original
        refresh_cookie_value = cookies_set[1].split(";")[0].split("=", 1)[1]
        assert fernet.decrypt(refresh_cookie_value.encode()).decode() == refresh_token


def test_cognito_login_cookie_domain(client, cfg, access_token, token_response):
    # set a domain for the cookie
    client.application.config["AWS_COGNITO_COOKIE_DOMAIN"] = ".example.com"

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A="

        # returns OK and sets the cookie
        response = client.get("/postlogin")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that the cookie is being set with the correct domain configuration
        assert "Domain=example.com" in response.headers["Set-Cookie"]


def test_cognito_login_cookie_samesite(client, cfg, access_token, token_response):
    # set a domain for the cookie
    client.application.config["AWS_COGNITO_COOKIE_DOMAIN"] = ".example.com"
    client.application.config["AWS_COGNITO_COOKIE_SAMESITE"] = "Strict"

    with client as c:
        with c.session_transaction() as sess:
            sess["code_verifier"] = "1234"
            sess["state"] = "5678"
            sess["nonce"] = "MSln6nvPIIBVMhsNUOtUCtssceUKz4dhCRZi5QZRU4A="

        # returns OK and sets the cookie
        response = client.get("/postlogin")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that the cookie is being set with the correct domain configuration
        assert "Domain=example.com" in response.headers["Set-Cookie"]
        assert "SameSite=Strict" in response.headers["Set-Cookie"]


def test_cognito_refresh_disabled(
    client,
    cfg,
    access_token,
    refresh_token_response,
):
    with pytest.raises(CognitoError, match="Refresh flow is not enabled"):
        client.get("/refresh")


def test_cognito_refresh_missing_token(
    client,
    cfg,
    access_token,
    refresh_token_response,
):
    client.application.config["AWS_COGNITO_REFRESH_FLOW_ENABLED"] = True

    with pytest.raises(CognitoError, match="No refresh token provided"):
        client.get("/refresh")


def test_cognito_refresh_callback(
    client_with_cookie_refresh,
    cfg,
    access_token,
    refresh_token,
    refresh_token_response,
):
    with client_with_cookie_refresh as c:
        # returns OK and sets the cookie
        response = c.get("/refresh")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that both access and refresh token is set in the cookie
        cookies_set = response.headers.getlist("Set-Cookie")
        assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}={access_token}")
        assert cookies_set[1].startswith(f"{cfg.COOKIE_NAME_REFRESH}={refresh_token}")

        # check that user claims and user info are stored in the session
        assert "claims" in session
        assert "user_info" in session


def test_cognito_refresh_callback_encrypted(
    client_with_cookie_refresh_encrypted,
    cfg,
    access_token,
    refresh_token,
    refresh_token_response,
):
    fernet = Fernet(
        urlsafe_b64encode(sha256(cfg.secret_key.encode()).digest()),
    )

    with client_with_cookie_refresh_encrypted as c:
        # returns OK and sets the cookie
        response = c.get("/refresh")
        assert response.status_code == 200
        assert response.data.decode("utf-8") == "ok"

        # check that both access and refresh token is set in the cookie
        cookies_set = response.headers.getlist("Set-Cookie")
        assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}={access_token}")
        assert cookies_set[1].startswith(f"{cfg.COOKIE_NAME_REFRESH}=")

        # check that the refresh token can be decrypted using Fernet and matches the original
        refresh_cookie_value = cookies_set[1].split(";")[0].split("=", 1)[1]
        assert fernet.decrypt(refresh_cookie_value.encode()).decode() == refresh_token

        # check that user claims and user info are stored in the session
        assert "claims" in session
        assert "user_info" in session


def test_cognito_logout(client, cfg):
    # should 302 redirect to cognito
    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.logout_endpoint)


def test_cognito_logout_with_refresh_token(client_with_cookie_refresh, cfg, mocker):
    # Mock the refresh token revocation
    mocker.patch(
        "flask_cognito_lib.decorators.cognito_auth.revoke_refresh_token",
    )

    # should 302 redirect to cognito
    response = client_with_cookie_refresh.get("/logout")
    assert response.status_code == 302
    assert response.headers["location"].startswith(cfg.logout_endpoint)

    # check that both access and refresh token is set in the cookie
    cookies_set = response.headers.getlist("Set-Cookie")
    assert cookies_set[0].startswith(f"{cfg.COOKIE_NAME}=;")
    assert cookies_set[1].startswith(f"{cfg.COOKIE_NAME_REFRESH}=;")


def test_auth_required_expired_token(client, cfg, app, access_token):
    # 403 if the token verification has failed
    app.config["AWS_COGNITO_EXPIRATION_LEEWAY"] = 0
    client.set_cookie(key=cfg.COOKIE_NAME, value=access_token)
    response = client.get("/private")
    assert response.status_code == 403


def test_auth_required_valid_token(client_with_cookie):
    # 200 if the token passes verification
    response = client_with_cookie.get("/private")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_all_groups_valid(client_with_cookie):
    # Has access to this route as the token has the correct group membership
    response = client_with_cookie.get("/valid_group")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_all_groups_invalid(client_with_cookie):
    # 403 as the token isn't in this group
    response = client_with_cookie.get("/invalid_group")
    assert response.status_code == 403


def test_auth_required_extension_dislabled(client, app):
    # Return page with 200 OK if the extension is disabled (bypass Cognito)
    app.config["AWS_COGNITO_DISABLED"] = True
    response = client.get("/private")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_any_group_valid_group1(client_with_cookie, mocker):
    # Mock the token verfication to add an extra group for testing
    # valid groups are "editor" and "admin"
    mocker.patch(
        "flask_cognito_lib.decorators.cognito_auth.verify_access_token",
        return_value={"cognito:groups": ["editor", "another_group"]},
    )

    # Has access to this route as the token has the correct group membership
    response = client_with_cookie.get("/any_group")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_any_group_valid_group2(client_with_cookie, mocker):
    # Mock the token verfication to add an extra group for testing
    # valid groups are "editor" and "admin"
    mocker.patch(
        "flask_cognito_lib.decorators.cognito_auth.verify_access_token",
        return_value={"cognito:groups": ["admin", "group2"]},
    )

    # Has access to this route as the token has the correct group membership
    response = client_with_cookie.get("/any_group")
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_auth_required_any_group_invalid(client_with_cookie, mocker):
    # Mock the token verfication to add an extra group for testing
    # valid groups are "editor" and "admin"
    mocker.patch(
        "flask_cognito_lib.decorators.cognito_auth.verify_access_token",
        return_value={"cognito:groups": ["group1", "group2"]},
    )

    # Does not have access to this route, not in any valid group
    response = client_with_cookie.get("/any_group")
    assert response.status_code == 403
