"""Layer 1: AAuth agent identity -- Ed25519 keys and agent token minting.

Implements the identity primitives described in the AAuth Internet-Draft
(draft-hardt-oauth-aauth-protocol): an agent identifier of the form
``aauth:<name>@<domain>``, an Ed25519 keypair for that agent, and signed
JWT "agent tokens" asserting the identifier.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_JWT_ALGORITHM = "EdDSA"
_AGENT_ID_RE = re.compile(r"^aauth:[^@\s]+@[^@\s]+$")


class InvalidAgentIdentifier(ValueError):
    """Raised when an agent identifier does not match the ``aauth:name@domain`` form."""


def validate_agent_id(agent_id: str) -> str:
    if not _AGENT_ID_RE.match(agent_id):
        raise InvalidAgentIdentifier(
            f"agent_id must look like 'aauth:name@domain', got {agent_id!r}"
        )
    return agent_id


@dataclass
class AgentIdentity:
    """An AAuth agent's identifier plus its Ed25519 keypair."""

    agent_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def __post_init__(self) -> None:
        validate_agent_id(self.agent_id)

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def mint_agent_token(
        self,
        *,
        audience: str | None = None,
        ttl: datetime.timedelta = datetime.timedelta(minutes=5),
        extra_claims: dict | None = None,
    ) -> str:
        """Mint a signed EdDSA JWT agent token asserting this identity's agent_id."""
        now = datetime.datetime.now(datetime.timezone.utc)
        claims = {
            "sub": self.agent_id,
            "iat": now,
            "exp": now + ttl,
        }
        if audience is not None:
            claims["aud"] = audience
        if extra_claims:
            claims.update(extra_claims)
        return jwt.encode(claims, self.private_key_pem(), algorithm=_JWT_ALGORITHM)


def generate_identity(agent_id: str) -> AgentIdentity:
    """Generate a fresh Ed25519 keypair for the given agent identifier."""
    private_key = Ed25519PrivateKey.generate()
    return AgentIdentity(
        agent_id=agent_id,
        private_key=private_key,
        public_key=private_key.public_key(),
    )


def load_identity(agent_id: str, private_key_pem: bytes) -> AgentIdentity:
    """Load an agent identity from an existing Ed25519 private key (PEM-encoded)."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key_pem must encode an Ed25519 private key")
    return AgentIdentity(
        agent_id=agent_id,
        private_key=private_key,
        public_key=private_key.public_key(),
    )


def verify_agent_token(token: str, public_key_pem: bytes, *, audience: str | None = None) -> dict:
    """Verify a signed agent token and return its claims."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    return jwt.decode(
        token,
        public_key,
        algorithms=[_JWT_ALGORITHM],
        audience=audience,
        options={"require": ["sub", "iat", "exp"], "verify_aud": audience is not None},
    )
