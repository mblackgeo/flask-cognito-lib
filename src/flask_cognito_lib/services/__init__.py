from flask_cognito_lib.config import Config
from flask_cognito_lib.services.cognito_svc import CognitoService
from flask_cognito_lib.services.token_svc import TokenService


def cognito_service_factory(cfg: Config):
    return CognitoService(cfg=cfg)


def token_service_factory(cfg: Config):
    return TokenService(cfg=cfg)
