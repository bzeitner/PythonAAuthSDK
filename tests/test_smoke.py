"""Smoke test: mint an Ed25519-keyed agent token and produce a verifiable
RFC 9421 signature over a sample HTTP request."""

import requests

from aauth import RequestSigner, RequestVerifier, generate_identity
from aauth.identity import verify_agent_token


def test_mint_and_verify_agent_token():
    identity = generate_identity("aauth:demo-agent@example.com")

    token = identity.mint_agent_token(audience="aauth:resource@example.com")
    claims = verify_agent_token(
        token, identity.public_key_pem(), audience="aauth:resource@example.com"
    )

    assert claims["sub"] == "aauth:demo-agent@example.com"
    assert claims["aud"] == "aauth:resource@example.com"


def test_sign_and_verify_request():
    identity = generate_identity("aauth:demo-agent@example.com")
    key_id = identity.agent_id

    request = requests.Request(
        "POST",
        "https://example.com/resource",
        data=b'{"hello": "world"}',
    ).prepare()

    signer = RequestSigner(key_id, identity.private_key)
    signer.sign(request)

    assert "Signature" in request.headers
    assert "Signature-Input" in request.headers

    verifier = RequestVerifier(key_id, identity.public_key)
    results = verifier.verify(request)

    assert len(results) == 1
    assert results[0].parameters["keyid"] == key_id
    assert results[0].parameters["alg"] == "ed25519"
