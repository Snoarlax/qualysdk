"""
basic.py - contains the BasicAuth class, which handles API endpoints that require basic authentication
"""

from dataclasses import dataclass, field
from typing import Literal, Union

from requests import get

from .base import BaseAuthentication
from ..exceptions import AuthenticationError


@dataclass
class BasicAuth(BaseAuthentication):
    """
    BasicAuth - handles API endpoints that require basic authentication

    Subclass of .base.BaseAuthentication - provides the basic authentication for the API

    Attributes:
    ```
    region: str - the region for the basic authentication. Defaults to "US1", but can be any of the regions defined by Qualys.
    ```
    Other attributes are inherited from BaseAuthentication - AKA username, password, token, and auth_type
    """

    def __post_init__(self) -> None:
        """
        Post-init method to determine auth_type based on if a token is passed or not.
        """
        region_map = {
            "US1":"https://qualysapi.qualys.com",
            "US2":"https://qualysapi.qg2.apps.qualys.com",
            "US3":"https://qualysapi.qg3.apps.qualys.com",
            "US4":"https://qualysapi.qg4.apps.qualys.com",
            "EU1":"https://qualysapi.qualys.eu",
            "EU2":"https://qualysapi.qg2.apps.qualys.eu",
            "EU3":"https://qualysapi.qg3.apps.qualys.it",
            "IN1":"https://qualysapi.qg1.apps.qualys.in",
            "CA1":"https://qualysapi.qg1.apps.qualys.ca",
            "AE1":"https://qualysapi.qg1.apps.qualys.ae",
            "UK1":"https://qualysapi.qg1.apps.qualys.co.uk",
            "AU1":"https://qualysapi.qg1.apps.qualys.com.au",
            "KSA1":"https://qualysapi.qg1.apps.qualysksa.com",
        }

        if self.region not in region_map:
            raise ValueError("region must be a valid Qualys region. ")

        self.url = region_map[self.region]

        super().__post_init__()
        self.validate_type()
        # self.auth_type = "basic"
        if self.auth_type == "basic":  # account for TokenAuth
            self.test_login()

    def __str__(self) -> str:
        """
        String representation of the authentication object.
        """
        return f"Basic authentication object for {self.username} on {self.region} region."

    def to_dict(self) -> dict:
        """
        Convert the authentication object to a dictionary.
        """
        return {
            "username": self.username,
            "password": self.password,
            "token": self.token,
            "auth_type": self.auth_type,
            "region": self.region,
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def test_login(self, return_ratelimit: bool = False) -> Union[dict, None]:
        """
        Get the rate limit for the API.

        Params:
        ```
        return_ratelimit: bool (default is False) - whether to return the rate limit details as a dict or not.
        You should call get_ratelimit() to get the rate limit details.
        ```

        Returns:
        ```
        {
            "X-RateLimit-Remaining": int,
            "X-RateLimit-Limit": int,
            "X-Concurrency-Limit-Limit": int,
            "X-RateLimit-ToWait-Sec": int
        }
        """

        (
            print(
                f"Testing login for {self.username} on {self.region} region via {self.auth_type} authentication."
            )
            if not return_ratelimit
            else None
        )

        url = f"{self.url}/msp/about.php"

        """Requires basic auth. JWT is not supported for this endpoint."""
        r = get(url, auth=(self.username, self.password))

        if r.status_code != 200:
            raise AuthenticationError(f"Failed to authenticate. Requests reporting: {r.text}")

        rl = {
            "X-RateLimit-Limit": int(r.headers["X-RateLimit-Limit"]),
            "X-Concurrency-Limit-Limit": int(r.headers["X-Concurrency-Limit-Limit"]),
        }
        print(f"Success. Rate limit details: {rl}") if not return_ratelimit else None
        return rl if return_ratelimit else None

    def get_ratelimit(self) -> dict:
        """
        Return ratelimit details for the API.
        """
        return self.test_login(return_ratelimit=True)
