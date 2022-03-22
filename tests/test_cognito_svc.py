from flask_cognito_lib.services.cognito_svc import CognitoService


def test_base_url(cfg):
    cognito = CognitoService(cfg)
    assert cognito.cfg.domain == "http://auth.example.com"


def test_sign_in_url(cfg):
    cognito = CognitoService(cfg)
    res = cognito.get_sign_in_url(
        code_challenge="asdf",
        state="1234",
        nonce="6789",
        scopes=["openid", "profile"],
    )
    assert res == (
        "http://auth.example.com/oauth2/authorize"
        "?response_type=code"
        "&client_id=545isk1een1lvilb9en643g3vd"
        "&redirect_uri=http%3A//example.com/redirect"
        "&state=1234"
        "&nonce=6789"
        "&code_challenge=asdf"
        "&code_challenge_method=S256"
        "&scopes=openid+profile"
    )


def test_exchange_code_for_token(cfg, token_endpoint_request):
    cognito = CognitoService(cfg)
    token = cognito.exchange_code_for_token(
        code="test_code", code_verifier="asdf", requests_client=token_endpoint_request
    )
    assert token == "test_access_token"
