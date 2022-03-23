from werkzeug.exceptions import HTTPException


class FlaskCognitoError(Exception):
    pass


class ConfigurationError(FlaskCognitoError):
    pass


class TokenVerifyError(FlaskCognitoError):
    pass


class CognitoError(FlaskCognitoError):
    pass


class AuthorisationRequiredError(HTTPException):
    code = 403


class CognitoGroupRequiredError(HTTPException):
    code = 403
