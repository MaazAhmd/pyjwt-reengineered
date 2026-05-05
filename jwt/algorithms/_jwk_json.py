from __future__ import annotations

import json

from ..exceptions import InvalidKeyError
from ..types import JWKDict


def _parse_jwk_json_input(jwk: str | JWKDict) -> JWKDict:
    # parsing jwk string or dict into a normalized dict object
    try:
        if isinstance(jwk, str):
            obj: JWKDict = json.loads(jwk)
        elif isinstance(jwk, dict):
            obj = jwk
        else:
            raise ValueError
    except ValueError:
        raise InvalidKeyError("Key is not valid JSON") from None
    return obj
