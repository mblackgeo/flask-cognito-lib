from werkzeug.exceptions import HTTPException


class ConfigurationError(Exception):
    pass


class TokenVerifyError(Exception):
    pass


class CognitoError(Exception):
    pass


class AuthorisationRequiredError(HTTPException):
    code = 403
