from config import Config
from flask import Flask, jsonify, redirect, session, url_for

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.decorators import (
    auth_required,
    cognito_login,
    cognito_login_callback,
    cognito_logout,
)
from flask_cognito_lib.exceptions import AuthorisationRequiredError

app = Flask(__name__)

app.config.from_object(Config)

auth = CognitoAuth(app)


@app.route("/")
def home():
    return "Hello world!"


@app.route("/login")
@cognito_login
def login():
    # No logic is required as the decorator ensure a redirect to the Cognito
    # hosted UI for the user to sign in
    pass


@app.route("/postlogin")
@cognito_login_callback
def postlogin():
    # A route to handle the redirect after a user has logged in with Cognito.
    # The decorator will store the validated access token in a HTTP only cookie
    # and the user claims are stored in the Flask session (session["claims"]).
    # This route must be set as one of the User Pool client's Callback URLs.
    # Do anything login after the user has logged in here, e.g. a redirect
    return redirect(url_for("claims"))


@app.route("/claims")
@auth_required()
def claims():
    # This route is protected by the Cognito authorisation. If the user is not
    # logged in at this point or their token from Cognito is no longer valid
    # a 401 Authentication Error is thrown, which is caught here a redirected
    # to login.
    # If their session is valid, the claims from the Cognito JWT will be shown
    return jsonify(session)


@app.errorhandler(AuthorisationRequiredError)
def login_redirect_handler(err):
    # Register an error handler if the user hits an "@auth_required" route
    # but is not logged in to redirect them to the Cognito UI
    return redirect(url_for("login"))


@app.route("/logout")
@cognito_logout
def logout():
    # Logout of the Cognito User pool and delete the cookies that were set
    # on login.
    # No logic is required here as it simply redirects to Cognito
    pass


@app.route("/postlogout")
def postlogout():
    # This is the endpoint Cognito redirects to after a user has logged out,
    # handle any logic here, like returning to the homepage.
    # This route must be set as one of the User Pool client's Sign Out URLs.
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
