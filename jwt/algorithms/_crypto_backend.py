from __future__ import annotations

import sys
from typing import Union

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1,
        EllipticCurve,
        EllipticCurvePrivateKey,
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives.asymmetric.ed448 import (
        Ed448PrivateKey,
        Ed448PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPrivateNumbers,
        RSAPublicKey,
        RSAPublicNumbers,
        rsa_crt_dmp1,
        rsa_crt_dmq1,
        rsa_crt_iqmp,
        rsa_recover_prime_factors,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
        load_ssh_public_key,
    )
    from cryptography.hazmat.primitives.asymmetric.types import (
        PrivateKeyTypes,
        PublicKeyTypes,
    )

    if sys.version_info >= (3, 10):
        from typing import TypeAlias
    else:
        from typing_extensions import TypeAlias

    AllowedRSAKeys: TypeAlias = Union[RSAPrivateKey, RSAPublicKey]
    AllowedECKeys: TypeAlias = Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]
    AllowedOKPKeys: TypeAlias = Union[
        Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey
    ]
    AllowedKeys: TypeAlias = Union[AllowedRSAKeys, AllowedECKeys, AllowedOKPKeys]
    AllowedPrivateKeys: TypeAlias = Union[
        RSAPrivateKey, EllipticCurvePrivateKey, Ed25519PrivateKey, Ed448PrivateKey
    ]
    AllowedPublicKeys: TypeAlias = Union[
        RSAPublicKey, EllipticCurvePublicKey, Ed25519PublicKey, Ed448PublicKey
    ]

    has_crypto = True
except ModuleNotFoundError:
    if sys.version_info >= (3, 11):
        from typing import Never
    else:
        from typing_extensions import Never

    AllowedRSAKeys = Never  # type: ignore[misc]
    AllowedECKeys = Never  # type: ignore[misc]
    AllowedOKPKeys = Never  # type: ignore[misc]
    AllowedKeys = Never  # type: ignore[misc]
    AllowedPrivateKeys = Never  # type: ignore[misc]
    AllowedPublicKeys = Never  # type: ignore[misc]
    has_crypto = False
