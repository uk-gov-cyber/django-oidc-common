import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings

from oidc_common import backchannel

KID = "test-key"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def jwks(rsa_key, monkeypatch):
    """Serve a JWKS holding rsa_key's public half instead of fetching Keycloak's."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk["kid"] = KID
    monkeypatch.setattr(backchannel, "_jwks_cache", {"keys": [jwk]})


@pytest.fixture
def make_logout_token(rsa_key):
    """Builds a logout_token; keyword args override or (with None) drop claims."""

    def _make(kid=KID, key=None, **overrides):
        claims = {
            "iss": settings.REALM_URL,
            "aud": settings.OIDC_RP_CLIENT_ID,
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
            "events": {backchannel.BACKCHANNEL_LOGOUT_EVENT: {}},
            "sid": "kc-session-1",
            "sub": "user-1",
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(
            claims, key or rsa_key, algorithm="RS256", headers={"kid": kid}
        )

    return _make
