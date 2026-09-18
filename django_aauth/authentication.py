"""Django/DRF resource-server integration: verify AAuth-signed requests.

A resource server built on this SDK doesn't know an incoming agent's key id
in advance -- it's only revealed once the request's ``Signature-Input``
header is parsed. ``AAuthAuthentication`` extracts that key id, asks the
subclass to resolve it to an Ed25519 public key, then verifies the request
per RFC 9421 using the existing :class:`~django_aauth.signing.RequestVerifier`.
"""

from __future__ import annotations

import dataclasses
import logging
import re

from rest_framework import authentication, exceptions

from .signing import RequestVerifier

logger = logging.getLogger(__name__)

# Matches the first keyid="..." parameter in a Signature-Input header.
# The AAuth draft currently assumes a single signature per request; if a
# future revision requires multi-signature resource-server requests, this
# will need to iterate all sig*= labels instead of taking the first match.
_KEYID_RE = re.compile(r'keyid="([^"]*)"')


@dataclasses.dataclass(frozen=True)
class AAuthAgent:
    """The ``request.user`` DRF sees after a successful AAuth verification.

    Satisfies the "user" half of DRF's authentication contract (an
    ``is_authenticated`` attribute) so this backend composes with DRF's
    built-in permission classes such as ``IsAuthenticated``.
    """

    agent_id: str
    is_authenticated: bool = True

    def __str__(self) -> str:
        return self.agent_id


class _VerifiableRequest:
    """Adapts a Django/DRF request to the ``(method, url, headers)`` shape
    that ``http_message_signatures`` verifies against."""

    def __init__(self, request) -> None:
        self.method = request.method
        self.url = request.build_absolute_uri()
        self.headers = request.headers


def _extract_key_id(signature_input_header: str) -> str | None:
    match = _KEYID_RE.search(signature_input_header)
    return match.group(1) if match else None


class AAuthAuthentication(authentication.BaseAuthentication):
    """DRF authentication backend that verifies RFC 9421 signed AAuth requests.

    Subclass and implement ``resolve_public_key`` to look up the requesting
    agent's Ed25519 public key (e.g. from a database keyed by agent id).
    """

    def resolve_public_key(self, key_id: str):
        raise NotImplementedError(
            "Subclasses must implement resolve_public_key() to look up the "
            "Ed25519 public key for a given AAuth key id."
        )

    def authenticate(self, request):
        signature_input = request.headers.get("Signature-Input")
        if not signature_input:
            return None  # no AAuth signature present; let other authenticators try

        key_id = _extract_key_id(signature_input)
        if key_id is None:
            raise exceptions.AuthenticationFailed("malformed Signature-Input header")

        try:
            public_key = self.resolve_public_key(key_id)
        except KeyError:
            raise exceptions.AuthenticationFailed(f"unknown AAuth key id: {key_id!r}")

        verifier = RequestVerifier(key_id, public_key)
        try:
            results = verifier.verify(_VerifiableRequest(request))
        except Exception:
            logger.warning("AAuth signature verification failed for key id %r", key_id, exc_info=True)
            raise exceptions.AuthenticationFailed("AAuth signature verification failed")

        if not results:
            raise exceptions.AuthenticationFailed("no verifiable AAuth signature found")

        return (AAuthAgent(agent_id=key_id), results)
