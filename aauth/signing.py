"""Layer 1: RFC 9421 HTTP Message Signatures for AAuth agent requests.

Thin wrapper around ``http_message_signatures`` (the pyauth implementation of
RFC 9421) configured for AAuth's required Ed25519 signature algorithm.
"""

from __future__ import annotations

import datetime
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)

DEFAULT_COVERED_COMPONENTS: Sequence[str] = ("@method", "@authority", "@target-uri")


class StaticKeyResolver(HTTPSignatureKeyResolver):
    """Resolves a single fixed keypair, keyed by the agent's key id."""

    def __init__(
        self,
        key_id: str,
        *,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
    ) -> None:
        self.key_id = key_id
        self._private_key = private_key
        self._public_key = public_key or (private_key.public_key() if private_key else None)

    def resolve_public_key(self, key_id: str) -> Ed25519PublicKey:
        if key_id != self.key_id or self._public_key is None:
            raise KeyError(f"no public key for key_id={key_id!r}")
        return self._public_key

    def resolve_private_key(self, key_id: str) -> Ed25519PrivateKey:
        if key_id != self.key_id or self._private_key is None:
            raise KeyError(f"no private key for key_id={key_id!r}")
        return self._private_key


class RequestSigner:
    """Signs outgoing HTTP requests per RFC 9421 using an Ed25519 key."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519,
            key_resolver=StaticKeyResolver(key_id, private_key=private_key),
        )

    def sign(self, request, *, covered_components: Sequence[str] = DEFAULT_COVERED_COMPONENTS):
        """Sign a ``requests.PreparedRequest``-shaped object in place, returning it."""
        self._signer.sign(
            request,
            key_id=self.key_id,
            created=datetime.datetime.now(datetime.timezone.utc),
            covered_component_ids=covered_components,
        )
        return request


class RequestVerifier:
    """Verifies RFC 9421 signatures on incoming HTTP requests using an Ed25519 key."""

    def __init__(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        self.key_id = key_id
        self._verifier = HTTPMessageVerifier(
            signature_algorithm=algorithms.ED25519,
            key_resolver=StaticKeyResolver(key_id, public_key=public_key),
        )

    def verify(self, request, *, max_age: datetime.timedelta = datetime.timedelta(minutes=5)):
        """Verify a signed request, returning the list of verified signature results."""
        return self._verifier.verify(request, max_age=max_age)
