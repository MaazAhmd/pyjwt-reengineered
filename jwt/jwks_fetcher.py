from __future__ import annotations

import json
import urllib.request
from ssl import SSLContext
from typing import Any
from urllib.error import HTTPError, URLError

from .exceptions import PyJWKClientConnectionError


class JWKSFetcher:
    def __init__(
        self,
        uri: str,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
    ) -> None:
        self.uri = uri
        self.headers = headers or {}
        self.timeout = timeout
        self.ssl_context = ssl_context

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        :returns: The parsed JSON response.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        """
        try:
            request = urllib.request.Request(url=self.uri, headers=self.headers)
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.ssl_context
            ) as response:
                return json.load(response)
        except (URLError, TimeoutError) as exc:
            if isinstance(exc, HTTPError):
                exc.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{exc}"'
            ) from exc
