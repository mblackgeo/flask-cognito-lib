from os import environ, path, urandom

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, session, url_for

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.decorators import (
    auth_required,
    cognito_login,
    cognito_login_callback,
    cognito_logout,
    cognito_refresh_callback,
)
from flask_cognito_lib.exceptions import (
    AuthorisationRequiredError,
    CognitoGroupRequiredError,
)

# Load variables from .env
basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, ".env"))


class Config:
    """Set Flask configuration vars from .env file."""

    # General Config
    SECRET_KEY = environ.get("SECRET_KEY", urandom(32))
    FLASK_APP = "TEST_APP"
    FLASK_ENV = "TESTING"

    # Cognito config
    # AWS_COGNITO_DISABLED = True  # Can set to turn off auth (e.g. for local testing)
    AWS_REGION = environ["AWS_REGION"]
    AWS_COGNITO_USER_POOL_ID = environ["AWS_COGNITO_USER_POOL_ID"]
    AWS_COGNITO_DOMAIN = environ["AWS_COGNITO_DOMAIN"]
    AWS_COGNITO_USER_POOL_CLIENT_ID = environ["AWS_COGNITO_USER_POOL_CLIENT_ID"]
    AWS_COGNITO_USER_POOL_CLIENT_SECRET = environ["AWS_COGNITO_USER_POOL_CLIENT_SECRET"]
    AWS_COGNITO_REDIRECT_URL = environ["AWS_COGNITO_REDIRECT_URL"]
    AWS_COGNITO_LOGOUT_URL = environ["AWS_COGNITO_LOGOUT_URL"]
    AWS_COGNITO_COOKIE_AGE_SECONDS = environ["AWS_COGNITO_COOKIE_AGE_SECONDS"]
    AWS_COGNITO_REFRESH_FLOW_ENABLED = environ["AWS_COGNITO_REFRESH_FLOW_ENABLED"]
    AWS_COGNITO_REFRESH_COOKIE_ENCRYPTED = environ[
        "AWS_COGNITO_REFRESH_COOKIE_ENCRYPTED"
    ]


app = Flask(__name__)
app.config.from_object(Config)
auth = CognitoAuth(app)


@app.route("/")
def home():
    return "Hello world!"


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


@app.route("/refresh", methods=["POST"])
@cognito_refresh_callback
def refresh():
    # A route to handle the token refresh with Cognito.
    # The decorator will exchange the refresh token, previously stored in the session,
    # for the new access and refresh tokens.
    # The new validated access token will be stored in an HTTP only secure cookie.
    # The refresh token will be symmetrically encrypted(by default)
    # and stored in an HTTP only secure cookie.
    # The user claims and info are stored in the Flask session:
    # session["claims"] and session["user_info"].
    # Do anything after the user has refreshed access token here, e.g. a redirect
    # or perform logic based on the `session["user_info"]`.
    pass


@app.route("/claims")
@auth_required()
def claims():
    # This route is protected by the Cognito authorisation. If the user is not
    # logged in at this point or their token from Cognito is no longer valid
    # a 401 Authentication Error is thrown, which is caught by the
    # `auth_error_handler` a redirected to the Hosted UI to login.
    # If their auth is valid, the current session will be shown including
    # their claims and user_info extracted from the Cognito tokens.
    return jsonify(session)


@app.errorhandler(AuthorisationRequiredError)
def auth_error_handler(err):
    # Register an error handler if the user hits an "@auth_required" route
    # but is not logged in to redirect them to the Cognito UI
    return redirect(url_for("login"))


@app.route("/admin")
@auth_required(groups=["admin"])
def admin():
    # This route will only be accessible to a user who is a member of all of
    # groups specified in the "groups" argument on the auth_required decorator
    # If they are not, a CognitoGroupRequiredError is raised which is handled
    # by the `missing_group_error_handler` below.
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
    # below.
    return jsonify(session["claims"]["cognito:groups"])


@app.errorhandler(CognitoGroupRequiredError)
def missing_group_error_handler(err):
    # Register an error handler if the user hits an "@auth_required" route
    # but is not in all of groups specified
    return jsonify("Group membership does not allow access to this resource"), 403


@app.route("/logout")
@cognito_logout
def logout():
    # Logout of the Cognito User pool and delete the cookies that were set
    # on login.
    # Revokes the refresh token to not be used again and removes it from the session.
    # No logic is required here as it simply redirects to Cognito.
    pass


@app.route("/postlogout")
def postlogout():
    # This is the endpoint Cognito redirects to after a user has logged out,
    # handle any logic here, like returning to the homepage.
    # This route must be set as one of the User Pool client's Sign Out URLs.
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
