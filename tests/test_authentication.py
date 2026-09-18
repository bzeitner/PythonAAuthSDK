"""Resource-server integration: verify RFC 9421 signed requests via the DRF
authentication backend."""

import pytest
import requests
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from django_aauth import RequestSigner, generate_identity
from django_aauth.authentication import AAuthAuthentication


def _sign(method, url, key_id, private_key):
    """Sign a request per RFC 9421 and return its Signature headers."""
    prepared = requests.Request(method, url).prepare()
    RequestSigner(key_id, private_key).sign(prepared)
    return {
        "Signature": prepared.headers["Signature"],
        "Signature-Input": prepared.headers["Signature-Input"],
    }


class _KnownAgentAuthentication(AAuthAuthentication):
    """Test double: resolves the one identity registered in ``known_keys``."""

    def __init__(self, known_keys):
        self.known_keys = known_keys

    def resolve_public_key(self, key_id):
        return self.known_keys[key_id]


def test_authenticates_validly_signed_request():
    identity = generate_identity("aauth:demo-agent@example.com")
    url = "http://testserver/resource"
    sig_headers = _sign("GET", url, identity.agent_id, identity.private_key)

    django_request = APIRequestFactory().get(
        "/resource",
        HTTP_SIGNATURE=sig_headers["Signature"],
        HTTP_SIGNATURE_INPUT=sig_headers["Signature-Input"],
    )
    request = Request(django_request)

    backend = _KnownAgentAuthentication({identity.agent_id: identity.public_key})
    agent_id, results = backend.authenticate(request)

    assert agent_id == identity.agent_id
    assert len(results) == 1
    assert results[0].parameters["keyid"] == identity.agent_id


def test_returns_none_when_unsigned():
    django_request = APIRequestFactory().get("/resource")
    request = Request(django_request)

    backend = _KnownAgentAuthentication({})
    assert backend.authenticate(request) is None


def test_rejects_unknown_key_id():
    identity = generate_identity("aauth:demo-agent@example.com")
    url = "http://testserver/resource"
    sig_headers = _sign("GET", url, identity.agent_id, identity.private_key)

    django_request = APIRequestFactory().get(
        "/resource",
        HTTP_SIGNATURE=sig_headers["Signature"],
        HTTP_SIGNATURE_INPUT=sig_headers["Signature-Input"],
    )
    request = Request(django_request)

    backend = _KnownAgentAuthentication({})  # no known agents
    with pytest.raises(Exception):
        backend.authenticate(request)


def test_rejects_tampered_signature():
    identity = generate_identity("aauth:demo-agent@example.com")
    other_identity = generate_identity("aauth:demo-agent@example.com")
    url = "http://testserver/resource"
    sig_headers = _sign("GET", url, identity.agent_id, identity.private_key)

    django_request = APIRequestFactory().get(
        "/resource",
        HTTP_SIGNATURE=sig_headers["Signature"],
        HTTP_SIGNATURE_INPUT=sig_headers["Signature-Input"],
    )
    request = Request(django_request)

    # Resolves to the wrong public key for this key id -> signature won't verify.
    backend = _KnownAgentAuthentication({identity.agent_id: other_identity.public_key})
    with pytest.raises(Exception):
        backend.authenticate(request)
