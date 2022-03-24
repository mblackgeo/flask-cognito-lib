# Setting up a Cognito User Pool and client

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
    - Under "Allowed callback URLs" add the URL of the route that has the `@cognito_login_callback` - for the example app this should be `http://localhost:5000/postlogin`
    - Expand the "Advanced app client settings"
        - Set the Refresh, Access, and ID Token expiration values to the desired session length for the user (note that refresh tokens are not used)
        - Locate the "Add Signout URL" button and add the URL of the route handles logic after logout - for the example app this should be `http://localhost:5000/postlogout`
- Review all settings and hit "Create"
- After creation, add users and groups as required