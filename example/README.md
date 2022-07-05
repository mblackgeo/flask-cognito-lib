# Example application - `flask-cognito-lib`

## Getting started

To get start with the example, follow the steps below to setup a user pool and then run the example application.

### Setup a Cognito user pool

Cognito is a serverless offering from Amazon Web Services that allows for sign-up/sign-in and user management with OAuth 2.0 and OpenID Connect, as well as federated identities through social identity providers (e.g. Google, Facebook, Amazon) and SAML. It has a generous free tier, with 50,000 monthly active users from the Cognito IdP. To get start protecting routes in your Flask app, first create a new Cognito User Pool and a client for the application:

- Visit the AWS Cognito console, click to create a new user pool ("Add user directories to your app")
- Step 1: Ensure the "Cognito user pool" provider is checked, choose any additional sign-in options as required
- Step 2: Configure your security requirements as needed (e.g. Multi-Factor Authentication, password policy)
- Step 3: Configure your sign-up experience as required, or leave to defaults
- Step 4: Configure message delivery, for production apps you should use SES, for testing "Send email with Cognito" is sufficient
- Step 5: Integrate your app
    - Name the user pool
    - Check the box to enable the Hosted UI
    - Setup a domain for the user pool (either a custom domain or the domain prefix)
    - Choose "Confidential Client"
    - Set the "App client name"
    - Ensure the box is checked to "Create a client secret"
    - Under "Allowed callback URLs" add the URL of the route that has the `@cognito_login_callback` - for the example this should be `http://localhost:5000/postlogin`
    - Expand the "Advanced app client settings"
        - Set the Refresh, Access, and ID Token expiration values to the desired session length for the user (note that refresh tokens are not used)
        - Locate the "Add Signout URL" button and add the URL of the route handles logic after logout - for the example this should be `http://localhost:5000/postlogout`
- Review all settings and hit "Create"
- After creation, add users and groups as required


After setting up the user pool, there are a number of values to note that are required for configuration of the Flask app:

| **Config Name**                       | **Description**                                                                      | **Required**     |
|---------------------------------------|--------------------------------------------------------------------------------------|------------------|
| `SECRET_KEY`                          | Secret key for the Flask app, required to store create the session cookies           | Y                |
| `AWS_REGION`                          | Region the user pool was created                                                     | Y                |
| `AWS_COGNITO_DOMAIN`                  | The domain name of the user pool (from Step 2)                                       | Y                |
| `AWS_COGNITO_USER_POOL_ID`            | The ID of the user pool                                                              | Y                |
| `AWS_COGNITO_USER_POOL_CLIENT_ID`     | The user pool app client ID (*)                                                      | Y                |
| `AWS_COGNITO_USER_POOL_CLIENT_SECRET` | The user pool app client secret (*)                                                  | Y                |
| `AWS_COGNITO_REDIRECT_URL`            | The full URL of the route that handles post-login flow (Step 7)                      | Y                |
| `AWS_COGNITO_LOGOUT_URL`              | The full URL of the route that handles post-logout flow (Step 8)                     | Y                |
| `AWS_COGNITO_COOKIE_AGE_SECONDS`      | Age of the access token cookie. Same as token expiration setting in Cognito (Step 8) | N (default 1800) |

(*) Navigate to the user pool in the AWS Cognito console, then head to the "App Integration" tab. Under the app client list, select the app client and you should be able to view the Client ID and Client Secret

### Run the app locally

```python
# create a virtual env
python -m venv /path/to/new/virtual/environment

# install the requirements
python -m pip install -r requirements.txt

# populate the environment variables with values from Cognito User Pool
cp .env.example .env
vi .env

# run the app
flask run
```

The app will launch at [`http://localhost:5000`](http://localhost:5000). Visit the [`/login`](http://localhost:5000/login) endpoint and you will be redirected to the Cognito hosted UI to sign in. After sign-in, you will be redirected back to the app, through the `/postlogin` endpoint which will exchange the access code from Cognito for an access token (and ID token, if openid is part of the default scopes), verify the JSON Web Token(s) (JWT) that are returned, storing the `claims` and `user_info` in the current secure Flask session, as well as storing the access token in a secure HTTP only cookie. Following this routes can be protected with the `auth_required()` decorator (for example, the [`/claims`](http://localhost:5000/claims) route), or additional role-based access control can be implemented through Cognito Groups (for example, the [`/admin`](http://localhost:5000/admin) route).
