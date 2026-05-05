# Refactoring: JWT Claim Validation Layer (`jwt/api_jwt.py`)

## Why the refactoring was necessary

`PyJWT` had two distinct responsibilities tangled together:

1. **JWT orchestration** — parsing options, delegating signature work to `PyJWS`, deserialising the payload.
2. **Claim policy enforcement** — deciding whether `exp` has expired, whether `aud` matches, whether `iss` is valid, and so on.

This violated the Single Responsibility Principle. The nine private `_validate_*` methods lived directly on `PyJWT`, but none of them used any instance state (`self`). They only operated on the `payload` dict and their arguments. This is the textbook signal that methods belong somewhere else.

Concrete problems that motivated the change:

| Problem | Location |
|---|---|
| `_merge_options` mutated the caller's dict (silent side-effect) | `api_jwt.py:80-88` |
| `timedelta` → `float` normalisation was scattered (done once in `_validate_claims`, but callers still had to pass the raw value) | `api_jwt.py:388-389` |
| `_validate_aud` hid two completely independent code paths (strict vs. lenient) under one `if strict:` branch, inflating cyclomatic complexity | `api_jwt.py:510-558` |
| Four parameters (`audience`, `issuer`, `subject`, `leeway`) were threaded identically through `decode_complete` → `_validate_claims` → individual validators | `api_jwt.py:272-279`, `379-387` |
| The "if `verify_signature=False`, default all `verify_x` to False" implication rule had no canonical home | `api_jwt.py:80-88` |

---

## What was done

### 1. Extract Class → `jwt/claims.py`

**Catalog entry:** *Extract Class* (Moving Features Between Objects)

A new module `jwt/claims.py` was created containing three classes. All claim-validation policy now lives here; `PyJWT` contains no validation logic.

---

### 2. Introduce Parameter Object → `ValidationContext`

**Catalog entry:** *Introduce Parameter Object* (Making Method Calls Simpler)

The four per-call validation parameters `audience`, `issuer`, `subject`, and `leeway` were always passed together through every layer. They are now bundled into a single dataclass:

```python
@dataclass
class ValidationContext:
    audience: str | Iterable[str] | None = None
    issuer:   str | Container[str] | None = None
    subject:  str | None = None
    leeway:   float = 0.0          # always seconds; normalised on construction
```

The `build()` classmethod accepts `leeway` as either `float` or `timedelta` and normalises it to seconds internally. This removes the `isinstance(leeway, timedelta)` conversion that previously sat at the top of `_validate_claims`.

**Before:**
```python
# PyJWT._validate_claims
def _validate_claims(self, payload, options, audience, issuer, subject, leeway):
    if isinstance(leeway, timedelta):
        leeway = leeway.total_seconds()
    ...
```

**After:**
```python
# call site in decode_complete
_claim_validator.validate(
    payload,
    merged_options,
    ValidationContext.build(audience=audience, issuer=issuer, subject=subject, leeway=leeway),
)
```

---

### 3. Replace Data Value with Object → `DecodeOptions`

**Catalog entry:** *Replace Data Value with Object* (Organising Data)

The options merge logic — including the critical rule *"when `verify_signature=False`, default every `verify_x` flag to `False` unless explicitly overridden"* — was previously an imperative procedure in `_merge_options` that also mutated the caller's dict. It is now encapsulated in a dataclass with a `build()` classmethod:

```python
@dataclass
class DecodeOptions:
    verify_signature: bool = True
    verify_exp: bool = True
    # ... all flags ...

    @classmethod
    def build(cls, base: dict, overrides: dict | None) -> "DecodeOptions":
        # applies verify_signature implications without mutating either dict
        ...
```

`PyJWT.__init__` and `decode_complete` both call `DecodeOptions.build(...)`. The public `self.options` dict interface is preserved via `as_full_options()`, so existing code that reads `jwt.options["verify_exp"]` continues to work unchanged.

**Before (side-effect bug):**
```python
def _merge_options(self, options):
    if not options.get("verify_signature", True):
        options["verify_exp"] = options.get("verify_exp", False)  # mutates caller's dict!
        ...
    return {**self.options, **options}
```

**After (no mutation, centralised rule):**
```python
@classmethod
def build(cls, base, overrides):
    effective = dict(overrides)          # copy — caller's dict is untouched
    if not effective.get("verify_signature", True):
        for flag in _VERIFY_CLAIM_FLAGS:
            effective.setdefault(flag, False)
    ...
```

---

### 4. Move Method → `ClaimValidator`

**Catalog entry:** *Move Method* (Moving Features Between Objects)

All nine `_validate_*` methods were moved from `PyJWT` into `ClaimValidator`. None of them referenced `self` on `PyJWT`; the move required no logic changes.

```
PyJWT (before)              →   ClaimValidator (after)
─────────────────────────────────────────────────────
_validate_claims            →   validate()
_validate_required_claims   →   _validate_required_claims()
_validate_exp               →   _validate_exp()
_validate_nbf               →   _validate_nbf()
_validate_iat               →   _validate_iat()
_validate_aud               →   _validate_aud()
_validate_iss               →   _validate_iss()
_validate_sub               →   _validate_sub()
_validate_jti               →   _validate_jti()
```

A module-level singleton `_claim_validator = ClaimValidator()` is used in `decode_complete` to avoid creating a new object on every decode call.

A thin delegation shim for `_validate_iss` is kept on `PyJWT` to preserve backward compatibility with the existing test suite, which calls `jwt._validate_iss(...)` directly.

---

### 5. Consolidate Conditional Expression → `_require_claim()`

**Catalog entry:** *Consolidate Conditional Expression* (Simplifying Conditional Expressions)

The pattern of "raise `MissingRequiredClaimError` if a claim is absent" appeared inline in multiple validators. It is now a single named helper:

```python
@staticmethod
def _require_claim(payload: dict, claim: str) -> None:
    if payload.get(claim) is None:
        raise MissingRequiredClaimError(claim)
```

`_validate_required_claims` uses it to reduce its loop body to one line. The `iss` and `aud` checks retain their explicit forms because they have different conditions (`"iss" not in payload` vs. `"aud" not in payload or not payload["aud"]`).

---

### 6. Decompose Conditional → `_validate_aud_strict` / `_validate_aud_lenient`

**Catalog entry:** *Decompose Conditional* (Simplifying Conditional Expressions)

`_validate_aud` previously contained two entirely independent code paths under a single `if strict:` branch. Each path had its own error messages and its own early returns. They are now extracted into two static methods, making `_validate_aud` a pure dispatcher:

```python
def _validate_aud(self, payload, audience, *, strict=False):
    # ... handle audience=None and missing-claim cases ...
    audience_claims = payload["aud"]
    if strict:
        self._validate_aud_strict(audience, audience_claims)
    else:
        self._validate_aud_lenient(audience, audience_claims)
```

The strict path enforces: single-string audience on both sides, exact equality.  
The lenient path enforces: list normalisation, string-element checks, any-match.

No error messages were changed.

---

## File map

```
jwt/
├── claims.py        ← NEW: ValidationContext, DecodeOptions, ClaimValidator
├── api_jwt.py       ← CHANGED: orchestration only; delegates to claims.py
└── (all other files unchanged)

docs/
└── refactoring-api-jwt.md   ← this file
```

## Risk and mitigation

The primary risk is a subtle change in exception type or message. Every exception class and every message string was copied verbatim from the original `_validate_*` implementations. The full existing test suite (`test_api_jwt.py`, `test_compressed_jwt.py`, `test_jwt.py`, `test_exceptions.py`) covers all claim-validation paths and should be run after each change to verify no regressions.
