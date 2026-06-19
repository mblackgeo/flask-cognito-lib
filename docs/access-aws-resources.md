# Accessing AWS Resources

Once your user is logged in, you will likely want them to be able to access other AWS resources based on their newly assumed role. There are a couple ways to do this, depending on how/what resources you want to access.

## E.g. Using an AppSync API

If you've setup an AppSync API and added the User Pool your user is part of as an authorization mode, you can use the cognito_access_token stored in an HTTP secure cookie to sign API requests:

```
import os
import requests

url = os.environ.get("AWS_APPSYNC_ENDPOINT")

query = """
query MyQuery {
    getMyObject(id: "1234567890abcdef") {
        date
        name
    }
}
"""

headers = {
    'Content-Type': 'application/graphql',
    'Authorization': request.cookies.get("cognito_access_token"),
}

response = requests.post(url, json={'query': query}, headers=headers)
```

## E.g. Accessing an S3 Bucket with Identity Pool Role

To access AWS resources directly (e.g. with boto), you will want to setup an Identity Pool with your User Pool (specifically with your app client ID) added as an identity provider and an Authenticated Role that has the necessary IAM permissions to access the resources you want. You can get credentials from the Identity Pool using the cognito_id_token stored in an HTTP secure cookie and then use those credentials to sign requests to boto:

```
import boto3
import os

def get_idp_credentials(session, request):
    cognito_client = boto3.client('cognito-identity')

    getIdResponse = cognito_client.get_id(
        AccountId=os.environ.get("AWS_ACCOUNT_ID"),
        IdentityPoolId=os.environ.get("AWS_COGNITO_IDENTITY_POOL_ID"),
        Logins={
            session["claims"]["iss"][8:]: request.cookies.get("cognito_id_token")
        }
    )
    
    getCredentialsResponse = cognito_client.get_credentials_for_identity(
        IdentityId=getIdResponse["IdentityId"],
        Logins={
            session["claims"]["iss"][8:]: request.cookies.get("cognito_id_token")
        }
    )

    return getCredentialsResponse

def get_aws_session(getCredentialsResponse):
    return boto3.Session(
        aws_access_key_id=getCredentialsResponse["Credentials"]["AccessKeyId"],
        aws_secret_access_key=getCredentialsResponse["Credentials"]["SecretKey"],
        aws_session_token=getCredentialsResponse["Credentials"]["SessionToken"],
    )
```