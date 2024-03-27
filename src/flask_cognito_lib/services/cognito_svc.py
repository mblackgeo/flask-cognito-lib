from typing import List, Optional
from urllib.parse import quote

import requests

from flask_cognito_lib.config import Config
from flask_cognito_lib.exceptions import CognitoError
from flask_cognito_lib.utils import CognitoTokenResponse


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
        nonce: str,
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
        nonce : str
            A random state string used for to prevent replay attacks
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
            f"&nonce={nonce}"
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
        )

        if scopes is not None:
            full_url += f"&scope={'+'.join(scopes)}"

        return full_url

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
    ) -> CognitoTokenResponse:
        """Exchange a short lived authorisation code for an access token

        Parameters
        ----------
        code : str
            The authorisation code after the user has logged in at the Cognito UI
        code_verifier : str
            The plaintext code verification secret used as the code challenge
            when logging in

        Returns
        -------
        CognitoTokenResponse
            A dataclass that holds the token response from Cognito

        Raises
        ------
        CognitoError
            If the request to the endpoint fails
            If the endpoint returns an error code
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self.cfg.user_pool_client_id,
            "redirect_uri": self.cfg.redirect_url,
            "code": code,
            "code_verifier": code_verifier,
        }

        return self._request_token(data)

    def refresh_token(
        self,
        refresh_token: str,
    ) -> CognitoTokenResponse:
        """
        Exchange a refresh token for a new set of tokens

        Parameters:
        -----------
        refresh_token : str
            The refresh token to exchange for a new set of tokens

        Returns:
        --------
        CognitoTokenResponse
            A dataclass that holds the token response from Cognito

        Raises:
        -------
        CognitoError
            If the request to the endpoint fails
            If the endpoint returns an error code
        """
        data = {
            "grant_type": "refresh_token",
            "client_id": self.cfg.user_pool_client_id,
            "refresh_token": refresh_token,
        }

        return self._request_token(data)

    def _request_token(self, data: dict) -> CognitoTokenResponse:
        """
        Request a token from the Cognito token endpoint

        Parameters
        ----------
        data : dict
            The data to be sent as part of the request

        Returns
        -------
        CognitoTokenResponse
            A dataclass that holds the token response from Cognito

        """
        # The Authorization header must not be present when using a
        # Public Client, we assume this when the secret is blank.
        # (Blank secrets are not supported on Confidential Clients)
        if self.cfg.user_pool_client_secret:
            auth = (self.cfg.user_pool_client_id, self.cfg.user_pool_client_secret)
        else:
            auth = None

        try:
            response = requests.post(
                url=self.cfg.token_endpoint,
                data=data,
                auth=auth,
            )
            response_json = response.json()

        except requests.exceptions.RequestException as e:
            raise CognitoError(str(e)) from e

        if "error" in response_json:
            raise CognitoError(f"Cognito error : {response_json['error']}")

        return CognitoTokenResponse(**response_json)
