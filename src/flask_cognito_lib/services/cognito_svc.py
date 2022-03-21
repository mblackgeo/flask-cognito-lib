from typing import Callable, List, Optional
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

    def get_sign_in_url(
        self,
        code_challenge: str,
        state: str,
        scopes: Optional[List[str]] = None,
    ) -> str:
        """Generate a sign URL against the AUTHORIZE endpoint

        Parameters
        ----------
        code_challenge : str
            A SHA256 hash of the code verifier used for this request.
            Note only S256 is support by AWS Cognito.
        state : str
            A random state string used for to prevent cross site request forgery
        scopes : Optional[List[str]]
            An optional list of system-reserved scopes or custom scopes that
            are associated with a client that can be requested.
            If the client doesn't request any scopes, the authentication server
            uses all scopes that are associated with the client.

        Returns
        -------
        str
            A front channel login URL for the AWS Cognito AUTHORIZE endpoint
        """
        quoted_redirect_url = quote(self.cfg.redirect_url)

        full_url = (
            f"{self.cfg.authorize_endpoint}"
            f"?response_type=code"
            f"&client_id={self.cfg.user_pool_client_id}"
            f"&redirect_uri={quoted_redirect_url}"
            f"&state={state}"
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
        )

        if scopes is not None:
            full_url += f"&scopes={'+'.join(scopes)}"

        return full_url

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
        requests_client: Optional[Callable] = None,
    ) -> str:
        """Exchange a short lived authorisation code for an access token

        Parameters
        ----------
        code : str
            The authorisation code after the user has logged in at the Cognito UI
        code_verifier : str
            The plaintext code verification secret used as the code challenge
            when logging in
        requests_client : Optional[Callable], optional
            A client used to make http request, by default uses request.post
            Used for mocking real requests in the unit tests

        Returns
        -------
        str
            An access token

        Raises
        ------
        CognitoError
            If the request to the endpoint fails or the endpoint does not
            return an access token
        """
        if not requests_client:
            requests_client = requests.post

        data = {
            "grant_type": "authorization_code",
            "client_id": self.cfg.user_pool_client_id,
            "redirect_uri": self.cfg.redirect_url,
            "code": code,
            "code_verifier": code_verifier,
        }

        try:
            response = requests_client(
                url=self.cfg.token_endpoint,
                data=data,
                auth=(self.cfg.user_pool_client_id, self.cfg.user_pool_client_secret),
            )
            response_json = response.json()

        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e

        if "access_token" not in response_json:
            raise CognitoError(f"no access token returned for code {response_json}")

        return response_json["access_token"]
