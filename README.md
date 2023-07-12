# Protect Flask routes with AWS Cognito

[![PyPI](https://img.shields.io/pypi/v/flask_cognito_lib?style=for-the-badge)](https://pypi.org/project/flask-cognito-lib/)
[![Docs](https://img.shields.io/github/actions/workflow/status/mblackgeo/flask-cognito-lib/docs.yml?label=DOCS&style=for-the-badge)](https://mblackgeo.github.io/flask-cognito-lib)
[![CI](https://img.shields.io/github/actions/workflow/status/mblackgeo/flask-cognito-lib/cicd.yml?label=CI&style=for-the-badge)](https://github.com/mblackgeo/flask-cognito-lib/actions)
[![codecov](https://img.shields.io/codecov/c/github/mblackgeo/flask-cognito-lib?style=for-the-badge&token=TGV2RMGNZ5)](https://codecov.io/gh/mblackgeo/flask-cognito-lib)

A Flask extension that supports protecting routes with AWS Cognito following [OAuth 2.1 best practices](https://oauth.net/2.1/). That means the full authorization code flow, including Proof Key for Code Exchange (RFC 7636) to prevent Cross Site Request Forgery (CSRF), along with secure storage of access tokens in HTTP only cookies (to prevent Cross Site Scripting attacks), and additional `nonce` validation (if using ID tokens) to prevent replay attacks.

**Documentation**: [https://mblackgeo.github.io/flask-cognito-lib](https://mblackgeo.github.io/flask-cognito-lib)

**Source Code**: [https://github.com/mblackgeo/flask-cognito-lib](https://github.com/mblackgeo/flask-cognito-lib)


## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install:

```bash
pip install flask-cognito-lib
```


## Quick start

To get started quickly, a complete example Flask application is provided in [`/example`](example/) including instructions on setting up a Cognito User Pool. A separate repo holds [a complete example app](https://github.com/mblackgeo/flask-cognito-jwt-example), including AWS CDK (Cloud Development Kit) code to deploy the application to API Gateway and Lambda, along with creation of a Cognito User Pool and Client. However, assuming a Cognito user pool has been setup with an app client (with Client ID and Secret), get started as follows:

```python
from flask import Flask, jsonify, redirect, session, url_for

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.decorators import (
    auth_required,
    cognito_login,
    cognito_login_callback,
    cognito_logout,
)

app = Flask(__name__)

# Configuration required for CognitoAuth
app.config["AWS_REGION"] = "eu-west-1"
app.config["AWS_COGNITO_USER_POOL_ID"] = "eu-west-1_qwerty"
app.config["AWS_COGNITO_DOMAIN"] = "https://app.auth.eu-west-1.amazoncognito.com"
app.config["AWS_COGNITO_USER_POOL_CLIENT_ID"] = "asdfghjkl1234asdf"
app.config["AWS_COGNITO_USER_POOL_CLIENT_SECRET"] = "zxcvbnm1234567890"
app.config["AWS_COGNITO_REDIRECT_URL"] = "https://example.com/postlogin"
app.config["AWS_COGNITO_LOGOUT_URL"] = "https://example.com/postlogout"

auth = CognitoAuth(app)


@app.route("/login")
@cognito_login
def login():
    # A simple route that will redirect to the Cognito Hosted UI.
    # No logic is required as the decorator handles the redirect to the Cognito
    # hosted UI for the user to sign in.
    # An optional "state" value can be set in the current session which will
    # be passed and then used in the postlogin route (after the user has logged
    # into the Cognito hosted UI); this could be used for dynamic redirects,
    # for example, set `session['state'] = "some_custom_value"` before passing
    # the user to this route
    pass


@app.route("/postlogin")
@cognito_login_callback
def postlogin():
    # A route to handle the redirect after a user has logged in with Cognito.
    # This route must be set as one of the User Pool client's Callback URLs in
    # the Cognito console and also as the config value AWS_COGNITO_REDIRECT_URL.
    # The decorator will store the validated access token in a HTTP only cookie
    # and the user claims and info are stored in the Flask session:
    # session["claims"] and session["user_info"].
    # Do anything after the user has logged in here, e.g. a redirect or perform
    # logic based on a custom `session['state']` value if that was set before
    # login
    return redirect(url_for("claims"))


@app.route("/claims")
@auth_required()
def claims():
    # This route is protected by the Cognito authorisation. If the user is not
    # logged in at this point or their token from Cognito is no longer valid
    # a 401 Authentication Error is thrown, which can be caught by registering
    # an `@app.error_handler(AuthorisationRequiredError)
    # If their auth is valid, the current session will be shown including
    # their claims and user_info extracted from the Cognito tokens.
    return jsonify(session)


@app.route("/admin")
@auth_required(groups=["admin"])
def admin():
    # This route will only be accessible to a user who is a member of all of
    # groups specified in the "groups" argument on the auth_required decorator
    # If they are not, a 401 Authentication Error is thrown, which can be caught
    # by registering an `@app.error_handler(CognitoGroupRequiredError).
    # If their auth is valid, the set of groups the user is a member of will be
    # shown.

    # Could also use: jsonify(session["user_info"]["cognito:groups"])
    return jsonify(session["claims"]["cognito:groups"])


@app.route("/edit")
@auth_required(groups=["admin", "editor"], any_group=True)
def edit():
    # This route will only be accessible to a user who is a member of any of
    # groups specified in the "groups" argument on the auth_required decorator
    # If they are not, a CognitoGroupRequiredError is raised which is handled
    # below
    return jsonify(session["claims"]["cognito:groups"])


@app.route("/logout")
@cognito_logout
def logout():
    # Logout of the Cognito User pool and delete the cookies that were set
    # on login.
    # No logic is required here as it simply redirects to Cognito.
    pass


@app.route("/postlogout")
def postlogout():
    # This is the endpoint Cognito redirects to after a user has logged out,
    # handle any logic here, like returning to the homepage.
    # This route must be set as one of the User Pool client's Sign Out URLs.
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run()
```


## Development

Prequisites:

* [poetry](https://python-poetry.org/)
* [pre-commit](https://pre-commit.com/)

The Makefile includes helpful commands setting a development environment, get started by installing the package into a new environment and setting up pre-commit by running `make install`. Run `make help` to see additional available commands (e.g. linting, testing and so on).

* [Pytest](https://docs.pytest.org/en/6.2.x/) is used for testing the application (see `/tests`).
* [MkDocs](https://www.mkdocs.org/) is used for generating docs and hosted with GH pages (see `/docs`).
* Code is linted using [flake8](https://flake8.pycqa.org/en/latest/)
* Code formatting is validated using [Black](https://github.com/psf/black)
* [pre-commit](https://pre-commit.com/) is used to run these checks locally before files are pushed to git
* The [Github Actions pipeline](.github/workflows/cicd.yml) runs these checks and tests
* [Semantic-release](https://python-semantic-release.readthedocs.io/en/latest/) is used with [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for automated releasing to PyPI


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Please make sure to update tests as appropriate and ensure 100% test coverage.


## Credits

This work started as a fork of the unmaintained [Flask-AWSCognito](https://github.com/cgauge/Flask-AWSCognito) extension, revising the implementation following OAuth 2.1 recommendations, with inspiration from [flask-cognito-auth](https://github.com/shrivastava-v-ankit/flask-cognito-auth). Whilst there are serveral Cognito extensions available for Flask, none of those implement OAuth 2.1 recommendations, with some plugins not even actively maintained.
