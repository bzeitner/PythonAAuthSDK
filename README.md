# django-aauth

A Python SDK for [AAuth](https://www.aauth.dev/), the agent
authentication/authorization protocol (draft-hardt-oauth-aauth-protocol),
with a **Django/DRF resource-server integration** as its differentiating
focus.

A more general-purpose Python AAuth implementation already exists on PyPI
under the name `aauth` (https://pypi.org/project/aauth/). This package is
scoped instead to first-class Django/DRF integration (middleware and DRF
authentication classes for verifying AAuth-signed requests), which the
existing package does not target.

Status: agent identity and RFC 9421 request signing (Layer 1), plus an
initial DRF resource-server authentication backend that verifies
AAuth-signed requests. Full Layer 2 (agent client, delegation) is not yet
implemented.

## Install

```bash
pip install -e .
# For the DRF resource-server authentication backend:
pip install -e ".[drf]"
```

## Usage

```python
from django_aauth import generate_identity, RequestSigner
import requests

identity = generate_identity("aauth:my-agent@example.com")

# Mint a signed EdDSA agent token asserting this identity.
token = identity.mint_agent_token(audience="aauth:resource@example.com")

# Sign an outgoing request per RFC 9421 (HTTP Message Signatures).
request = requests.Request("POST", "https://example.com/resource").prepare()
RequestSigner(identity.agent_id, identity.private_key).sign(request)
```

On the resource-server side, verify incoming AAuth-signed requests with the
DRF authentication backend:

```python
from django_aauth.authentication import AAuthAuthentication

class MyAAuthAuthentication(AAuthAuthentication):
    def resolve_public_key(self, key_id: str):
        # Look up the Ed25519 public key registered for this agent id,
        # e.g. from a database. Raise KeyError if it's unknown.
        return known_agents[key_id]
```

```python
# settings.py / a view's authentication_classes
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["myapp.auth.MyAAuthAuthentication"],
}
```

`authenticate()` returns `None` for unsigned requests (letting other
authenticators run), and raises `AuthenticationFailed` for a present but
invalid or unresolvable signature.

## Layer 1 scope

- Ed25519 keypair generation and loading from PEM (`django_aauth.identity`)
- Agent token minting/verification via `PyJWT` (EdDSA) (`django_aauth.identity`)
- RFC 9421 request signing/verification via `http-message-signatures`
  (`django_aauth.signing`)
- DRF resource-server authentication backend that verifies AAuth-signed
  requests (`django_aauth.authentication`, requires `djangorestframework`)

## Development

```bash
pip install -e ".[test]"
pytest
```
