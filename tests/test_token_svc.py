from flask_cognito_lib.config import Config
from flask_cognito_lib.services.token_svc import TokenService


def test_verify(jwks_endpoint_request):
    serv = TokenService(cfg=Config(), request_client=jwks_endpoint_request)
    token = (
        "eyJraWQiOiJwdjVrMkZkcSs1dVZnY2I0anJnQTc2SDdpVkd2QU80dU9taHBDaGVxVERvPSIsImFsZyI6IlJTMjU2In0."
        "eyJzdWIiOiJmOGNkZDc4MC0wODBkLTQ0YjQtOTVkMC0zZGRmZDg0YTJkNTgiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBlbWFpbCIsImF1dGhfdGltZSI6MTU2ODczNzA4NCwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTFfRHJ2ZDhyNFRNIiwiZXhwIjoxNTY4NzQwNjg0LCJpYXQiOjE1Njg3MzcwODQsInZlcnNpb24iOjIsImp0aSI6IjU0MDgxNDY4LWY5M2QtNGM3NC1hZmQ3LTEwMGMzNmU3OTIyZSIsImNsaWVudF9pZCI6IjU0NWlzazFlZW4xbHZpbGI5ZW42NDNnM3ZkIiwidXNlcm5hbWUiOiJ0ZXN0MTIzIn0."
        "eDVBgVDxJdFQjH98IFiyWW5GV-J-z2FXj8LzuGUIrGRXFsJG7w70NtZiIrrevqKbnYqjmRsMpOw3p4s08tv6iGWGTJSR_8unYUh3RvBaBvcGdSh8BMyCIlFgQO7_lacXrhDJO-V5wMlCQ5SFIMwuPfm_dBJhLMz5xStIf-nbNzrv_3x6x4fk_snYDve0PQb4d0XHM8ej14cIHsE6wxE_64dn9nUUfjAtLGav_XTeo90AiN8qs7WTIjWKSHXO--P9-SFUyG8MB3M3uiqt7IWRiIgnib8ZetJLLdhxlLPlOxujBF6csgtXwMpLEIdV96xnhtMnvh26PfgwAuvEjONc6g"
    )
    serv.verify(token, current_time=1568723786)
    assert serv.claims == {
        "sub": "f8cdd780-080d-44b4-95d0-3ddfd84a2d58",
        "token_use": "access",
        "scope": "openid email",
        "auth_time": 1568737084,
        "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Drvd8r4TM",
        "exp": 1568740684,
        "iat": 1568737084,
        "version": 2,
        "jti": "54081468-f93d-4c74-afd7-100c36e7922e",
        "client_id": "545isk1een1lvilb9en643g3vd",
        "username": "test123",
    }
