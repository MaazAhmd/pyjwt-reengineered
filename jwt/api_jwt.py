from __future__ import annotations

import json
import os
import warnings
from calendar import timegm
from collections.abc import Container, Iterable, Sequence
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Union, cast

from .api_jws import PyJWS, _ALGORITHM_UNSET, _jws_global_obj
from .claims import ClaimValidator, DecodeOptions, ValidationContext
from .exceptions import DecodeError
from .warnings import RemovedInPyjwt3Warning

if TYPE_CHECKING or bool(os.getenv("SPHINX_BUILD", "")):
    import sys

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        # Python 3.9 and lower
        from typing_extensions import TypeAlias

    from .algorithms import AllowedPrivateKeys, AllowedPublicKeys
    from .api_jwk import PyJWK
    from .types import FullOptions, Options, SigOptions

    AllowedPrivateKeyTypes: TypeAlias = Union[AllowedPrivateKeys, PyJWK, str, bytes]
    AllowedPublicKeyTypes: TypeAlias = Union[AllowedPublicKeys, PyJWK, str, bytes]


_claim_validator = ClaimValidator()


class PyJWT:
    def __init__(self, options: Options | None = None) -> None:
        self.options: FullOptions = DecodeOptions.build(
            self._get_default_options(), options
        ).as_full_options()

        self._jws = PyJWS(options=self._get_sig_options())

    @staticmethod
    def _get_default_options() -> FullOptions:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_sub": True,
            "verify_jti": True,
            "require": [],
            "strict_aud": False,
            "enforce_minimum_key_length": False,
        }

    def _get_sig_options(self) -> SigOptions:
        return {
            "verify_signature": self.options["verify_signature"],
            "enforce_minimum_key_length": self.options.get(
                "enforce_minimum_key_length", False
            ),
        }

    def encode(
        self,
        payload: dict[str, Any],
        key: AllowedPrivateKeyTypes,
        algorithm: str | None = _ALGORITHM_UNSET,  # type: ignore[assignment]
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        """Encode the ``payload`` as JSON Web Token.

        :param payload: JWT claims, e.g. ``dict(iss=..., aud=..., sub=...)``
        :type payload: dict[str, typing.Any]
        :param key: a key suitable for the chosen algorithm:

            * for **asymmetric algorithms**: PEM-formatted private key, a multiline string
            * for **symmetric algorithms**: plain string, sufficiently long for security

        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPrivateKeys`
        :param algorithm: algorithm to sign the token with, e.g. ``"ES256"``.
            If ``headers`` includes ``alg``, it will be preferred to this parameter.
            If ``key`` is a :class:`PyJWK` object, by default the key algorithm will be used.
        :type algorithm: str or None
        :param headers: additional JWT header fields, e.g. ``dict(kid="my-key-id")``.
        :type headers: dict[str, typing.Any] or None
        :param json_encoder: custom JSON encoder for ``payload`` and ``headers``
        :type json_encoder: json.JSONEncoder or None

        :rtype: str
        :returns: a JSON Web Token

        :raises TypeError: if ``payload`` is not a ``dict``
        """
        # Check that we get a dict
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, as JWT only supports "
                "JSON objects as payloads."
            )

        # Payload
        payload = payload.copy()
        for time_claim in ["exp", "iat", "nbf"]:
            # Convert datetime to a intDate value in known time-format claims
            if isinstance(payload.get(time_claim), datetime):
                payload[time_claim] = timegm(payload[time_claim].utctimetuple())

        # Issue #1039, iss being set to non-string
        if "iss" in payload and not isinstance(payload["iss"], str):
            raise TypeError("Issuer (iss) must be a string.")

        json_payload = self._encode_payload(
            payload,
            headers=headers,
            json_encoder=json_encoder,
        )

        return self._jws.encode(
            json_payload,
            key,
            algorithm,
            headers,
            json_encoder,
            sort_headers=sort_headers,
        )

    def _encode_payload(
        self,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
    ) -> bytes:
        """
        Encode a given payload to the bytes to be signed.

        This method is intended to be overridden by subclasses that need to
        encode the payload in a different way, e.g. compress the payload.
        """
        return json.dumps(
            payload,
            separators=(",", ":"),
            cls=json_encoder,
        ).encode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeyTypes = "",
        algorithms: Sequence[str] | None = None,
        options: Options | None = None,
        # deprecated arg, remove in pyjwt3
        verify: bool | None = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: bytes | None = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
        # kwargs
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Identical to ``jwt.decode`` except for return value which is a dictionary containing the token header (JOSE Header),
        the token payload (JWT Payload), and token signature (JWT Signature) on the keys "header", "payload",
        and "signature" respectively.

        :param jwt: the token to be decoded
        :type jwt: str or bytes
        :param key: the key suitable for the allowed algorithm
        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPublicKeys`

        :param algorithms: allowed algorithms, e.g. ``["ES256"]``

            .. warning::

               Do **not** compute the ``algorithms`` parameter based on
               the ``alg`` from the token itself, or on any other data
               that an attacker may be able to influence, as that might
               expose you to various vulnerabilities (see `RFC 8725 §2.1
               <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
               either hard-code a fixed value for ``algorithms``, or
               configure it in the same place you configure the
               ``key``. Make sure not to mix symmetric and asymmetric
               algorithms that interpret the ``key`` in different ways
               (e.g. HS\\* and RS\\*).
        :type algorithms: typing.Sequence[str] or None

        :param jwt.types.Options options: extended decoding and validation options
            Refer to :py:class:`jwt.types.Options` for more information.

        :param audience: optional, the value for ``verify_aud`` check
        :type audience: str or typing.Iterable[str] or None
        :param issuer: optional, the value for ``verify_iss`` check
        :type issuer: str or typing.Container[str] or None
        :param leeway: a time margin in seconds for the expiration check
        :type leeway: float or datetime.timedelta
        :rtype: dict[str, typing.Any]
        :returns: Decoded JWT with the JOSE Header on the key ``header``, the JWS
         Payload on the key ``payload``, and the JWS Signature on the key ``signature``.
        """
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )

        if options is None:
            verify_signature = True
        else:
            verify_signature = options.get("verify_signature", True)

        # If the user has set the legacy `verify` argument, and it doesn't match
        # what the relevant `options` entry for the argument is, inform the user
        # that they're likely making a mistake.
        if verify is not None and verify != verify_signature:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
                stacklevel=2,
            )

        merged_options = DecodeOptions.build(self.options, options)

        sig_options: SigOptions = {
            "verify_signature": verify_signature,
        }
        decoded = self._jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=sig_options,
            detached_payload=detached_payload,
        )

        payload = self._decode_payload(decoded)

        _claim_validator.validate(
            payload,
            merged_options,
            ValidationContext.build(
                audience=audience,
                issuer=issuer,
                subject=subject,
                leeway=leeway,
            ),
        )

        decoded["payload"] = payload
        return decoded

    def _decode_payload(self, decoded: dict[str, Any]) -> dict[str, Any]:
        """
        Decode the payload from a JWS dictionary (payload, signature, header).

        This method is intended to be overridden by subclasses that need to
        decode the payload in a different way, e.g. decompress compressed
        payloads.
        """
        try:
            payload: dict[str, Any] = json.loads(decoded["payload"])
        except ValueError as e:
            raise DecodeError(f"Invalid payload string: {e}") from e
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")
        return payload

    def decode(
        self,
        jwt: str | bytes,
        key: AllowedPublicKeys | PyJWK | str | bytes = "",
        algorithms: Sequence[str] | None = None,
        options: Options | None = None,
        # deprecated arg, remove in pyjwt3
        verify: bool | None = None,
        # could be used as passthrough to api_jws, consider removal in pyjwt3
        detached_payload: bytes | None = None,
        # passthrough arguments to _validate_claims
        # consider putting in options
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | timedelta = 0,
        # kwargs
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Verify the ``jwt`` token signature and return the token claims.

        :param jwt: the token to be decoded
        :type jwt: str or bytes
        :param key: the key suitable for the allowed algorithm
        :type key: str or bytes or PyJWK or :py:class:`jwt.algorithms.AllowedPublicKeys`

        :param algorithms: allowed algorithms, e.g. ``["ES256"]``
            If ``key`` is a :class:`PyJWK` object, allowed algorithms will default to the key algorithm.

            .. warning::

               Do **not** compute the ``algorithms`` parameter based on
               the ``alg`` from the token itself, or on any other data
               that an attacker may be able to influence, as that might
               expose you to various vulnerabilities (see `RFC 8725 §2.1
               <https://www.rfc-editor.org/rfc/rfc8725.html#section-2.1>`_). Instead,
               either hard-code a fixed value for ``algorithms``, or
               configure it in the same place you configure the
               ``key``. Make sure not to mix symmetric and asymmetric
               algorithms that interpret the ``key`` in different ways
               (e.g. HS\\* and RS\\*).
        :type algorithms: typing.Sequence[str] or None

        :param jwt.types.Options options: extended decoding and validation options
            Refer to :py:class:`jwt.types.Options` for more information.

        :param audience: optional, the value for ``verify_aud`` check
        :type audience: str or typing.Iterable[str] or None
        :param subject: optional, the value for ``verify_sub`` check
        :type subject: str or None
        :param issuer: optional, the value for ``verify_iss`` check
        :type issuer: str or typing.Container[str] or None
        :param leeway: a time margin in seconds for the expiration check
        :type leeway: float or datetime.timedelta
        :rtype: dict[str, typing.Any]
        :returns: the JWT claims
        """
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            subject=subject,
            issuer=issuer,
            leeway=leeway,
        )
        return cast(dict[str, Any], decoded["payload"])

    # --- Delegation shim kept for backward compatibility with existing tests ---
    # _validate_iss is the only private method called directly in the test suite.
    # It forwards to ClaimValidator so PyJWT stays free of validation logic.

    def _validate_iss(
        self,
        payload: dict[str, Any],
        issuer: Container[str] | str | None,
    ) -> None:
        _claim_validator._validate_iss(payload, issuer)


_jwt_global_obj = PyJWT()
_jwt_global_obj._jws = _jws_global_obj
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
