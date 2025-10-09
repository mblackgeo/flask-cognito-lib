from flask_cognito_lib.config import Config
from flask_cognito_lib.services import cognito_service_factory, token_service_factory
from flask_cognito_lib.services.cognito_svc import CognitoService
from flask_cognito_lib.services.token_svc import TokenService


def test_cognito_service_factory(cfg: Config) -> None:
    assert isinstance(cognito_service_factory(cfg), CognitoService)


def test_token_service_factory(cfg: Config) -> None:
    assert isinstance(token_service_factory(cfg), TokenService)
