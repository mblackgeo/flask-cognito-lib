from base64 import b64encode
from urllib.parse import quote

import requests

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError


class CognitoService:
    def __init__(
        self,
        cfg: Config,
    ):
        self.cfg = cfg

    def get_sign_in_url(self):
        quoted_redirect_url = quote(self.cfg.redirect_url)

        # TODO state
        # os.urandom(16)
        # state = get_state(self.cfg.user_pool_id, self.cfg.user_pool_client_id)
        state = "asdf"

        # TODO authorize endpoint
        # TODO PKCE
        full_url = (
            f"{self.cfg.domain}/login"
            f"?response_type=code"
            f"&client_id={self.cfg.user_pool_client_id}"
            f"&redirect_uri={quoted_redirect_url}"
            f"&state={state}"
        )
        return full_url

    def exchange_code_for_token(self, code, requests_client=None):
        token_url = f"{self.cfg.domain}/oauth2/token"
        data = {
            "code": code,
            "redirect_uri": self.cfg.redirect_url,
            "client_id": self.cfg.user_pool_client_id,
            "grant_type": "authorization_code",
        }
        headers = {}
        if self.cfg.user_pool_client_secret:
            secret = b64encode(
                f"{self.cfg.user_pool_client_id}:{self.cfg.user_pool_client_secret}".encode(  # noqa: E501
                    "utf-8"
                )
            ).decode("utf-8")
            headers = {"Authorization": f"Basic {secret}"}
        try:
            if not requests_client:
                requests_client = requests.post
            response = requests_client(token_url, data=data, headers=headers)
            response_json = response.json()
        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e
        if "access_token" not in response_json:
            raise CognitoError(f"no access token returned for code {response_json}")
        access_token = response_json["access_token"]
        return access_token

    def get_user_info(self, access_token, requests_client=None):
        header = {"Authorization": f"Bearer {access_token}"}
        try:
            if not requests_client:
                requests_client = requests.post
            response = requests_client(self.cfg.user_info_endpoint, headers=header)
            response_json = response.json()
        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e
        return response_json
