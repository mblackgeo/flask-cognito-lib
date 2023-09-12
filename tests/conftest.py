import pytest
from flask import Flask, make_response
from jwt import PyJWKSet

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.config import Config
from flask_cognito_lib.decorators import (
    auth_required,
    cognito_login,
    cognito_login_callback,
    cognito_logout,
)
from flask_cognito_lib.utils import CognitoTokenResponse


@pytest.fixture(autouse=True)
def app():
    """Create application for the tests."""

    _app = Flask(__name__)
    CognitoAuth(_app)

    ctx = _app.test_request_context()
    ctx.push()

    _app.config["TESTING"] = True
    _app.config["PRESERVE_CONTEXT_ON_EXCEPTION"] = False
    _app.config["SECRET_KEY"] = "very-secure"

    # minimum require configuration for CognitoAuth extension
    _app.config["AWS_COGNITO_USER_POOL_ID"] = "us-east-1_HC5viybYt"
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "7og7do7m7tq0gi7ujm2uloa99v"
    _app.config["ADDITIONAL_AWS_COGNITO_USER_POOL_CLIENT_IDS"] = [
        "j7hha0k2v15pkkj7f8srkldud"
    ]
    _app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "secure-client-secret"
    _app.config["AWS_COGNITO_REDIRECT_URL"] = "http://localhost:5000/postlogin"
    _app.config["AWS_COGNITO_LOGOUT_URL"] = "http://localhost:5000/postlogout"
    _app.config[
        "AWS_COGNITO_DOMAIN"
    ] = "https://flask-cog-test.auth.us-east-1.amazoncognito.com"
    _app.config["AWS_REGION"] = "us-east-1"
    _app.config["AWS_COGNITO_EXPIRATION_LEEWAY"] = 1e9
    _app.config["AWS_COGNITO_COOKIE_AGE_SECONDS"] = 1e9

    _app.testing = True

    # ----------------
    # Testing routes
    # ----------------

    @_app.route("/login")
    @cognito_login
    def login():
        # 302 redirects to the cognito UI
        pass

    @_app.route("/postlogin")
    @cognito_login_callback
    def postlogin():
        # recieves the response from cognito and sets a cookie
        return make_response("ok")

    @_app.route("/logout")
    @cognito_logout
    def logout():
        # 302 redirects to the cognito UI to logout and deletes a cookie
        pass

    @_app.route("/private")
    @auth_required()
    def auth_req():
        # requires a valid access token to get a response
        # else raises AuthorisationRequiredError
        return make_response("ok")

    @_app.route("/valid_group")
    @auth_required(groups=["admin"])
    def group_req_valid():
        # sample token has admin group in "cognito:groups"
        return make_response("ok")

    @_app.route("/invalid_group")
    @auth_required(groups=["not_a_group"])
    def group_req_invalid():
        # Should throw 403 CognitoGroupRequiredError as the token is not in
        # the required group
        return make_response("ok")

    @_app.route("/any_group")
    @auth_required(groups=["admin", "editor"], any_group=True)
    def any_group_req_valid():
        return make_response("ok")

    yield _app
    ctx.pop()


@pytest.fixture
def client(app):
    cl = app.test_client()
    yield cl


@pytest.fixture
def jwks():
    return {
        "keys": [
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "gzj31u48EqJXelYMJv/KoEsxm7MPs38SKRNQ4Dn52w4=",
                "kty": "RSA",
                "n": "4E-KkPxBjSRkSFnzG1eATjmK6o--SAo4AONLHXHLbOXtvhaWwf7CsyP3t6oGcbx4gnx_b1-X1cXvUGjfW7a807gKSzQmj5yJerMwMAVMttar87qgCEzWOynuJMFH16sRLag1RPBGg6DVtE2NfbKn-65Ku5BVaEm_ca2TlP5-XdtZwhPoO05EPeKJjBhLLGpoBeQxEPvdPYSkwLEZTnIw_56EKdGbBN_EROvhNc8yLRgid8jVA737MKCBkYqwHicBH5a3s-7IYBVSG1LcmBSvq23zQ07sScetQaBGlb2uuVDBqV7rTnaMmWXqKvBF2P0mFci7i66KI8s9-dMwSd3x1w",
                "use": "sig",
            },
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "+p6XIZlM1nnLO+pQM2pBKFUZMJ7Ov2t7ijZT+GI/VHA=",
                "kty": "RSA",
                "n": "wzVaAJHhPF8BGWSo1XnRcR1_NXraynIt22tnE-sxY507S-gny7aIBlsSy8yDUdDgyxrcGQK7sCuhT5DYQqzgVfxMHumkdiKjOu33tgyJUBOuPUCI-7CglSDlZ2gvamY7vpZRZ8o2IvC-nZc039-otak6XKddsUbshoyKYN1_XAkrIQk0oARrCq89YOx5xVPIcD1QXg_QdF9dyOs6WNZC56yDA0cQKXMv840WwP1m2qnYgr5ryOdduQv6nrXF8ot3s2CT9eFn6B2keBHlbwkEmFREXe4wKcKuXHItiF7EEFxoDOmQpxM0BBm40MNe8Rz0awUjBA3Y-ckF7KEVChTc8Q",
                "use": "sig",
            },
        ]
    }


@pytest.fixture
def cfg():
    return Config()


@pytest.fixture(autouse=True)
def jwk_patch(mocker, jwks):
    # Return the keys from the user pool without hitting the real endpoint
    mocker.patch(
        "jwt.jwks_client.PyJWKClient.get_jwk_set",
        return_value=PyJWKSet.from_dict(jwks),
    )


@pytest.fixture
def access_token():
    return (
        "eyJraWQiOiIrcDZYSVpsTTFubkxPK3BRTTJwQktGVVpNSjdPdjJ0N2lqWlQrR0lcL1ZIQT0iLCJhbGciOiJSUzI1NiJ9."
        "eyJzdWIiOiI0OTk3MWQxYS1mNzIwLTQzMmMtYWJiYy05ZDQ2NmYyNjBkOTgiLCJjb2duaXRvOmdyb3VwcyI6WyJhZG1pbiJdLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9IQzV2aXliWXQiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiI3b2c3ZG83bTd0cTBnaTd1am0ydWxvYTk5diIsIm9yaWdpbl9qdGkiOiI2ZDU4ZjgyYy04NmRlLTQ0MTUtODE5Ni1hMmIzZGNjMTcwNzkiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6InBob25lIG9wZW5pZCBlbWFpbCIsImF1dGhfdGltZSI6MTY5NDQ5MDc0MywiZXhwIjoxNjk0NDk0MzQzLCJpYXQiOjE2OTQ0OTA3NDMsImp0aSI6IjRhYzVmMzJjLTI5YTYtNDE4MS1hNTcwLWJmNTJkMDNlOGIwNSIsInVzZXJuYW1lIjoiNDk5NzFkMWEtZjcyMC00MzJjLWFiYmMtOWQ0NjZmMjYwZDk4In0."
        "HYwmKO72vzwvWp6DRvegDfXdFzTBMaMzh0Ke8NeSKYN9AbLGEH5AZoREp68Y9AUliP9gqTH0F3eJem0Cw9JjmxfnlbNNfu6xcQMajy0GjGN38nPTQkuh4wZDFSBJpHWWIw22O4Jg9ZgWLA2N3KIepK0ZqCFvSSPOy61S_lMV-dvhXXzOE5mUt99ySrW84whtT6j2SlrL_EZiguZ2ElXMiMebr7oUbQ7dhg5uGF-3y46BiwchK4AoVNakphW7UnZ3iWbacf_7Vy0updRortmttB1N53GcWkAHlV5S7RfOoA8LmcKx8iuK4JOH1JOhwgXyJISOPRB59L8MCZWiWL23iw"
    )


@pytest.fixture
def additional_access_token():
    return (
        "eyJraWQiOiIrcDZYSVpsTTFubkxPK3BRTTJwQktGVVpNSjdPdjJ0N2lqWlQrR0lcL1ZIQT0iLCJhbGciOiJSUzI1NiJ9."
        "eyJzdWIiOiI0OTk3MWQxYS1mNzIwLTQzMmMtYWJiYy05ZDQ2NmYyNjBkOTgiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9IQzV2aXliWXQiLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiJqN2hoYTBrMnYxNXBra2o3ZjhzcmtsZHVkIiwib3JpZ2luX2p0aSI6ImE4MjhhNTIzLTc3YmEtNDZhNC1iYWVkLWRjZjcyOWViOGVjYyIsImV2ZW50X2lkIjoiNjEwOTZhNDMtYjA1ZC00MGExLWJkOTctYTM3MDFmNDI5ZjhlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJwaG9uZSBvcGVuaWQgZW1haWwiLCJhdXRoX3RpbWUiOjE2OTQyOTg0NDgsImV4cCI6MTY5NDMwMjA0OCwiaWF0IjoxNjk0Mjk4NDQ4LCJqdGkiOiJiYjVjNWY5MS1jMWZlLTQ3MDUtYWZkYS1mNjA4YWYzMTgyMjgiLCJ1c2VybmFtZSI6IjQ5OTcxZDFhLWY3MjAtNDMyYy1hYmJjLTlkNDY2ZjI2MGQ5OCJ9."
        "Y0LoHOZ_9VCpvjP0lUzTeOBHoYMlqSAsiUNXX5kPnHV4Ms2HjnvNEhsfQdTi5yq8YmUssFaM_-FVT2_wEJK8lKena2s0tt6L5IVAfcp7ia90kpV-2R0vj9XA-376XxPemI0vLjXaXGJgjTTukNU5k2nlOVdyi7EpGetKzLS-4-6PwpSOLcwyHzZIy7nzdJ66HBwHf_gJOq7ha3Txo74idMg2oMxIsu2vM09vGeQJOZYV2EqTkcCG44U9E4iZrc8LzFRc0zg7FGfT5K95A_kaHmYw44tPuXCaBE0BCzPSWMtdvumbQi-DJmIsDSQSo0mh4F1n71sJX8ML8nXX-HwppQ"
    )


@pytest.fixture
def id_token():
    return (
        "eyJraWQiOiJnemozMXU0OEVxSlhlbFlNSnZcL0tvRXN4bTdNUHMzOFNLUk5RNERuNTJ3ND0iLCJhbGciOiJSUzI1NiJ9."
        "eyJhdF9oYXNoIjoiOERMamZUV1N2UXVGZmVEb25RYVQ0dyIsInN1YiI6IjQ5OTcxZDFhLWY3MjAtNDMyYy1hYmJjLTlkNDY2ZjI2MGQ5OCIsImNvZ25pdG86Z3JvdXBzIjpbImFkbWluIl0sImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9IQzV2aXliWXQiLCJjb2duaXRvOnVzZXJuYW1lIjoiNDk5NzFkMWEtZjcyMC00MzJjLWFiYmMtOWQ0NjZmMjYwZDk4Iiwibm9uY2UiOiJNU2xuNm52UElJQlZNaHNOVU90VUN0c3NjZVVLejRkaENSWmk1UVpSVTRBPSIsIm9yaWdpbl9qdGkiOiI2ZDU4ZjgyYy04NmRlLTQ0MTUtODE5Ni1hMmIzZGNjMTcwNzkiLCJhdWQiOiI3b2c3ZG83bTd0cTBnaTd1am0ydWxvYTk5diIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjk0NDkwNzQzLCJleHAiOjE2OTQ0OTQzNDMsImlhdCI6MTY5NDQ5MDc0MywianRpIjoiZGQ3MTBkOGUtY2JlMC00Yjk4LTljN2MtYWFjZmY1OWU4YThjIiwiZW1haWwiOiJ0ZXN0QGZsYXNrY29nbml0by5jb20ifQ."
        "zSW8Fg6bXAlMRh5zBIS6YDTylVcXgIIuZ7VhxugvhQK7LU9WUiTQj7S_q_oImLVhfx_Mk4xm6DYsdYppJ7ppGYnFaxW_Ug6QHM632M0b7yj5wqZVZgtsEJuXoMddWh8oWBb1Y0VR1_enlinL_P56I0tumoqW8i21BXfFZC-r5WT3c_k0DR6d8kF9tHBtMnOpLgM4CqJC4acgFlHzZmCKVk_wSQUa2bOd4EPSTluUx3bwBMCNCqzxGls4LD58J_Hr5YfL1ZGJWwIKLhXHjBxyoARjIByMihhbRZSEeuvAR2R3BRysCfMVW38xAtxJF3YpQe7CU_Y93LSIXB23gNYsGw"
    )


@pytest.fixture
def additional_id_token():
    return (
        "eyJraWQiOiJnemozMXU0OEVxSlhlbFlNSnZcL0tvRXN4bTdNUHMzOFNLUk5RNERuNTJ3ND0iLCJhbGciOiJSUzI1NiJ9."
        "eyJhdF9oYXNoIjoiMkN6aGt0WHNtSEdwRlREZDVYT3JiQSIsInN1YiI6IjQ5OTcxZDFhLWY3MjAtNDMyYy1hYmJjLTlkNDY2ZjI2MGQ5OCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9IQzV2aXliWXQiLCJjb2duaXRvOnVzZXJuYW1lIjoiNDk5NzFkMWEtZjcyMC00MzJjLWFiYmMtOWQ0NjZmMjYwZDk4Iiwib3JpZ2luX2p0aSI6ImE4MjhhNTIzLTc3YmEtNDZhNC1iYWVkLWRjZjcyOWViOGVjYyIsImF1ZCI6Imo3aGhhMGsydjE1cGtrajdmOHNya2xkdWQiLCJldmVudF9pZCI6IjYxMDk2YTQzLWIwNWQtNDBhMS1iZDk3LWEzNzAxZjQyOWY4ZSIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNjk0Mjk4NDQ4LCJleHAiOjE2OTQzMDIwNDgsImlhdCI6MTY5NDI5ODQ0OCwianRpIjoiMTYzMTk2NjUtMDEwNy00MGZlLWJiNjEtM2EwYzgxY2ExMjY5IiwiZW1haWwiOiJ0ZXN0QGZsYXNrY29nbml0by5jb20ifQ."
        "uMJkZthqngYGL-bNWY3ZX0tRQsVtNLhvZagj6g58i-xRWTwEXhk3sGMIqRa_bkuA7mJvXkLm7oNd5Cb_Di844YA1p5HWikLsgxjF2eVQCNdMfHX130nbNnr7WFIge8YQY2ZCeedq3AsaS_25POvUjEKxEuJ8BGs8hvKHpJFTskWHhg5trserECpErLpRQqpvbPVvkRl92zxmGsKoREcjHlTKxtPMGTHjJtpkg9Xn-HmUtDF5ipy-RTLUGjs3JUyfkbqbkt9Hq6Hhf5DppViICLusF_iwiQbf4WBOxeJ8ahHUe_Fo3bCZjPoeeI7aB8lqF3olZEtvQfQum3eZE_SJ7g"
    )


@pytest.fixture(autouse=False)
def token_response(mocker, access_token, id_token):
    mocker.patch(
        "flask_cognito_lib.plugin.CognitoAuth.get_tokens",
        return_value=CognitoTokenResponse(access_token=access_token, id_token=id_token),
    )


@pytest.fixture
def client_with_cookie(app, access_token, cfg):
    cl = app.test_client()
    cl.set_cookie(key=cfg.COOKIE_NAME, value=access_token)
    yield cl
