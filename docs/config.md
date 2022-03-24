# Application configuration

## Cognito Auth extension configuration

The following key/value pairs are used for configurating the extension:

| **Config Name**                       | **Description**                                                                      |
|---------------------------------------|--------------------------------------------------------------------------------------|
| `AWS_REGION`                          | Region the user pool was created                                                     |
| `AWS_COGNITO_DOMAIN`                  | The domain name of the user pool                                                     |
| `AWS_COGNITO_USER_POOL_ID`            | The ID of the user pool                                                              |
| `AWS_COGNITO_USER_POOL_CLIENT_ID`     | The user pool app client ID (*)                                                      |
| `AWS_COGNITO_USER_POOL_CLIENT_SECRET` | The user pool app client secret (*)                                                  |
| `AWS_COGNITO_REDIRECT_URL`            | The full URL of the route that handles post-login flow                               |
| `AWS_COGNITO_LOGOUT_URL`              | The full URL of the route that handles post-logout flow                              |
| `AWS_COGNITO_COOKIE_AGE_SECONDS`      | (Optional) How long to store the access token cookie. (default=1800)                 |
| `AWS_COGNITO_EXPIRATION_LEEWAY`       | (Optional) Leeway (in seconds) when checking for token expiry (default=0)            |

(*) To obtain these values, navigate to the user pool in the AWS Cognito console, then head to the "App Integration" tab. Under the app client list, select the app client and you should be able to view the Client ID and Client Secret


## Example usage

These configuration should be setup and passed to the Flask app object, for example, if they are set in environment variables this could be achieved as follows:

```py
from os import environ
from flask import Flask

class Config:
    """Set Flask configuration vars from .env file."""

    # General Config
    SECRET_KEY = environ.get("SECRET_KEY", urandom(32))
    FLASK_APP = "TEST_APP"
    FLASK_ENV = "TESTING"

    # Cognito config
    AWS_REGION = environ["AWS_REGION"]
    AWS_COGNITO_USER_POOL_ID = environ["AWS_COGNITO_USER_POOL_ID"]
    AWS_COGNITO_DOMAIN = environ["AWS_COGNITO_DOMAIN"]
    AWS_COGNITO_USER_POOL_CLIENT_ID = environ["AWS_COGNITO_USER_POOL_CLIENT_ID"]
    AWS_COGNITO_USER_POOL_CLIENT_SECRET = environ["AWS_COGNITO_USER_POOL_CLIENT_SECRET"]
    AWS_COGNITO_REDIRECT_URL = environ["AWS_COGNITO_REDIRECT_URL"]
    AWS_COGNITO_LOGOUT_URL = environ["AWS_COGNITO_LOGOUT_URL"]

    # Optional
    # AWS_COGNITO_COOKIE_AGE_SECONDS = environ["AWS_COGNITO_COOKIE_AGE_SECONDS"]
    # AWS_COGNITO_EXPIRATION_LEEWAY = environ["AWS_COGNITO_EXPIRATION_LEEWAY]


app = Flask(__name__)
app.config.from_object(Config)
```