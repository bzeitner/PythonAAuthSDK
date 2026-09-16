# aauth (Python)

A Python SDK for [AAuth](https://www.aauth.dev/), the agent
authentication/authorization protocol (draft-hardt-oauth-aauth-protocol).

This is an early, general-purpose implementation, not scoped to any single
consumer. Status: **Layer 1 only** -- agent identity and RFC 9421 request
signing. Layer 2 (agent client / resource-server verification / delegation)
is not yet implemented.

## Install

```bash
pip install -e .
```

## Usage

```python
from aauth import generate_identity, RequestSigner
import requests

identity = generate_identity("aauth:my-agent@example.com")

# Mint a signed EdDSA agent token asserting this identity.
token = identity.mint_agent_token(audience="aauth:resource@example.com")

# Sign an outgoing request per RFC 9421 (HTTP Message Signatures).
request = requests.Request("POST", "https://example.com/resource").prepare()
RequestSigner(identity.agent_id, identity.private_key).sign(request)
```

## Layer 1 scope

- Ed25519 keypair generation and loading from PEM (`aauth.identity`)
- Agent token minting/verification via `PyJWT` (EdDSA) (`aauth.identity`)
- RFC 9421 request signing/verification via `http-message-signatures`
  (`aauth.signing`)

## Development

```bash
pip install -e ".[test]"
pytest
```
