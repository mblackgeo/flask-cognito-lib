from config import Config
from flask import Flask, jsonify, session

from flask_cognito_lib import CognitoAuth
from flask_cognito_lib.decorators import (
    auth_required,
    cognito_login,
    cognito_login_callback,
    cognito_logout,
)

app = Flask(__name__)

app.config.from_object(Config)

auth = CognitoAuth(app)


@app.route("/")
@cognito_login
def login():
    pass


@app.route("/postlogin")
@cognito_login_callback
def postlogin():
    pass


@app.route("/claims")
@auth_required()
def claims():
    return jsonify({"claims": session["claims"]})


@app.route("/logout")
@cognito_logout
def logout():
    pass


if __name__ == "__main__":
    app.run(debug=True, port=5000)
