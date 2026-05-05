from __future__ import annotations

from collections.abc import Container, Iterable
from dataclasses import dataclass, field, fields as dataclass_fields
from datetime import datetime, timedelta, timezone
from typing import Any

from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)

_VERIFY_CLAIM_FLAGS = (
    "verify_exp",
    "verify_nbf",
    "verify_iat",
    "verify_aud",
    "verify_iss",
    "verify_sub",
    "verify_jti",
)


@dataclass
class ValidationContext:
    """Per-call claim validation parameters. leeway is always stored as float seconds."""

    audience: str | Iterable[str] | None = None
    issuer: str | Container[str] | None = None
    subject: str | None = None
    leeway: float = 0.0

    @classmethod
    def build(
        cls,
        *,
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
    ) -> "ValidationContext":
        leeway_seconds = (
            leeway.total_seconds() if isinstance(leeway, timedelta) else float(leeway)
        )
        return cls(
            audience=audience,
            issuer=issuer,
            subject=subject,
            leeway=leeway_seconds,
        )


@dataclass
class DecodeOptions:
    """Fully-merged decode/validation options.

    Centralises the verify_signature→verify_x implication so that no caller
    needs to repeat that rule.  Build instances via DecodeOptions.build()
    rather than calling the constructor directly.
    """

    verify_signature: bool = True
    verify_exp: bool = True
    verify_nbf: bool = True
    verify_iat: bool = True
    verify_aud: bool = True
    verify_iss: bool = True
    verify_sub: bool = True
    verify_jti: bool = True
    require: list[str] = field(default_factory=list)
    strict_aud: bool = False
    enforce_minimum_key_length: bool = False

    @classmethod
    def build(
        cls, base: dict[str, Any], overrides: dict[str, Any] | None
    ) -> "DecodeOptions":
        """Merge *base* options dict with per-call *overrides*.

        When verify_signature=False is present in overrides, each verify_x
        flag is defaulted to False unless the caller set it explicitly.
        The incoming dicts are never mutated.
        """
        if overrides is None:
            effective: dict[str, Any] = {}
        else:
            effective = dict(overrides)
            if not effective.get("verify_signature", True):
                for flag in _VERIFY_CLAIM_FLAGS:
                    effective.setdefault(flag, False)

        merged = {**base, **effective}
        known = {f.name for f in dataclass_fields(cls)}
        return cls(**{k: v for k, v in merged.items() if k in known})

    def as_full_options(self) -> dict[str, Any]:
        """Return a FullOptions-compatible dict (preserves the public self.options interface)."""
        return {
            "verify_signature": self.verify_signature,
            "verify_exp": self.verify_exp,
            "verify_nbf": self.verify_nbf,
            "verify_iat": self.verify_iat,
            "verify_aud": self.verify_aud,
            "verify_iss": self.verify_iss,
            "verify_sub": self.verify_sub,
            "verify_jti": self.verify_jti,
            "require": self.require,
            "strict_aud": self.strict_aud,
            "enforce_minimum_key_length": self.enforce_minimum_key_length,
        }


class ClaimValidator:
    """Validates JWT claims against DecodeOptions and a ValidationContext.

    All policy decisions live here; PyJWT is responsible only for orchestration.
    """

    def validate(
        self,
        payload: dict[str, Any],
        options: DecodeOptions,
        context: ValidationContext,
    ) -> None:
        if context.audience is not None and not isinstance(
            context.audience, (str, Iterable)
        ):
            raise TypeError("audience must be a string, iterable or None")

        self._validate_required_claims(payload, options.require)

        now = datetime.now(tz=timezone.utc).timestamp()

        if "iat" in payload and options.verify_iat:
            self._validate_iat(payload, now, context.leeway)

        if "nbf" in payload and options.verify_nbf:
            self._validate_nbf(payload, now, context.leeway)

        if "exp" in payload and options.verify_exp:
            self._validate_exp(payload, now, context.leeway)

        if options.verify_iss:
            self._validate_iss(payload, context.issuer)

        if options.verify_aud:
            self._validate_aud(payload, context.audience, strict=options.strict_aud)

        if options.verify_sub:
            self._validate_sub(payload, context.subject)

        if options.verify_jti:
            self._validate_jti(payload)

    @staticmethod
    def _require_claim(payload: dict[str, Any], claim: str) -> None:
        if payload.get(claim) is None:
            raise MissingRequiredClaimError(claim)

    def _validate_required_claims(
        self,
        payload: dict[str, Any],
        claims: Iterable[str],
    ) -> None:
        for claim in claims:
            self._require_claim(payload, claim)

    @staticmethod
    def _validate_iat(payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            iat = int(payload["iat"])
        except ValueError:
            raise InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            ) from None
        if iat > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (iat)")

    @staticmethod
    def _validate_nbf(payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            nbf = int(payload["nbf"])
        except ValueError:
            raise DecodeError("Not Before claim (nbf) must be an integer.") from None
        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    @staticmethod
    def _validate_exp(payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError(
                "Expiration Time claim (exp) must be an integer."
            ) from None
        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(
        self,
        payload: dict[str, Any],
        audience: str | Iterable[str] | None,
        *,
        strict: bool = False,
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]
        if strict:
            self._validate_aud_strict(audience, audience_claims)
        else:
            self._validate_aud_lenient(audience, audience_claims)

    @staticmethod
    def _validate_aud_strict(
        audience: str | Iterable[str],
        audience_claims: Any,
    ) -> None:
        if not isinstance(audience, str):
            raise InvalidAudienceError("Invalid audience (strict)")
        if not isinstance(audience_claims, str):
            raise InvalidAudienceError("Invalid claim format in token (strict)")
        if audience != audience_claims:
            raise InvalidAudienceError("Audience doesn't match (strict)")

    @staticmethod
    def _validate_aud_lenient(
        audience: str | Iterable[str],
        audience_claims: Any,
    ) -> None:
        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")
        if isinstance(audience, str):
            audience = [audience]
        if all(aud not in audience_claims for aud in audience):
            raise InvalidAudienceError("Audience doesn't match")

    @staticmethod
    def _validate_iss(
        payload: dict[str, Any],
        issuer: Container[str] | str | None,
    ) -> None:
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        iss = payload["iss"]
        if not isinstance(iss, str):
            raise InvalidIssuerError("Payload Issuer (iss) must be a string")

        if isinstance(issuer, str):
            if iss != issuer:
                raise InvalidIssuerError("Invalid issuer")
        else:
            try:
                if iss not in issuer:
                    raise InvalidIssuerError("Invalid issuer")
            except TypeError:
                raise InvalidIssuerError(
                    'Issuer param must be "str" or "Container[str]"'
                ) from None

    @staticmethod
    def _validate_sub(
        payload: dict[str, Any],
        subject: str | None = None,
    ) -> None:
        if "sub" not in payload:
            return

        if not isinstance(payload["sub"], str):
            raise InvalidSubjectError("Subject must be a string")

        if subject is not None:
            if payload.get("sub") != subject:
                raise InvalidSubjectError("Invalid subject")

    @staticmethod
    def _validate_jti(payload: dict[str, Any]) -> None:
        if "jti" not in payload:
            return

        if not isinstance(payload.get("jti"), str):
            raise InvalidJTIError("JWT ID must be a string")
