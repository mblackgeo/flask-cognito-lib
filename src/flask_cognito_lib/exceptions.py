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
    description = "Authorization is required to access this resource."


class CognitoGroupRequiredError(HTTPException):
    code = 403
    description = "Cognito group membership is required to access this resource."
