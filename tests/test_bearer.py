import json
import time
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import HttpResponse
from django.test import RequestFactory

from oidc_common.bearer import (
    BearerTokenVerifier,
    InsufficientScope,
    InvalidBearerToken,
    bearer_token_required,
)

ISSUER = "https://keycloak.example.test/realms/TEST"
KID = "api-key"


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(*pairs):
    keys = []
    for kid, k in pairs:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key()))
        jwk.update(kid=kid, use="sig")
        keys.append(jwk)
    return {"keys": keys}


@pytest.fixture
def fetch(key):
    """Patches the JWKS fetch; .return_value.json.return_value is the served JWKS."""
    with mock.patch("oidc_common.bearer.requests.get") as get:
        get.return_value.json.return_value = _jwks((KID, key))
        yield get


@pytest.fixture
def verifier():
    return BearerTokenVerifier(issuer=ISSUER, audience="my-api")


def make(key, kid=KID, alg="RS256", **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": ["my-api", "account"], "sub": "sa-1", "azp": "caller-app",
              "typ": "Bearer", "iat": now, "exp": now + 300, "scope": "profile things:create"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def test_valid(fetch, verifier, key):
    claims = verifier.verify(make(key), scopes=["things:create"])
    assert claims["azp"] == "caller-app"
    assert fetch.call_args.args[0] == f"{ISSUER}/protocol/openid-connect/certs"


@pytest.mark.parametrize("overrides", [
    {"iss": "https://evil.example/realms/TEST"},
    {"iss": ISSUER + "x"},
    {"aud": "other-api"},
    {"exp": int(time.time()) - 5},
    {"exp": None},
    {"sub": None},
    {"typ": "ID"},
    {"typ": "Refresh"},
])
def test_rejected(fetch, verifier, key, overrides):
    with pytest.raises(InvalidBearerToken):
        verifier.verify(make(key, **overrides))


def test_missing_scope(fetch, verifier, key):
    with pytest.raises(InsufficientScope):
        verifier.verify(make(key, scope="profile"), scopes=["things:create"])
    with pytest.raises(InsufficientScope):
        # A scope name that merely contains the required one doesn't count.
        verifier.verify(make(key, scope="things:create-extra"), scopes=["things:create"])


def test_wrong_key(fetch, verifier):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(InvalidBearerToken):
        verifier.verify(make(other))


def test_hs256_with_public_key_refused(fetch, verifier, key):
    token = jwt.encode({"iss": ISSUER}, "a-shared-secret-of-at-least-32-bytes", algorithm="HS256", headers={"kid": KID})
    with pytest.raises(InvalidBearerToken, match="algorithm"):
        verifier.verify(token)


def test_unknown_kid_refetches_once_then_cools_down(fetch, verifier, key):
    verifier.verify(make(key))
    assert fetch.call_count == 1
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fetch.return_value.json.return_value = _jwks((KID, key), ("rotated", new))
    verifier._fetched_at -= BearerTokenVerifier.REFRESH_COOLDOWN + 1
    assert verifier.verify(make(new, kid="rotated"))["sub"] == "sa-1"
    assert fetch.call_count == 2
    with pytest.raises(InvalidBearerToken, match="unknown key"):
        verifier.verify(make(new, kid="made-up"))
    assert fetch.call_count == 2


def test_issuer_and_audience_required():
    with pytest.raises(ValueError):
        BearerTokenVerifier(issuer=ISSUER, audience="")


def _view(request):
    return HttpResponse(request.bearer_claims["azp"])


def test_decorator(fetch, verifier, key):
    view = bearer_token_required(verifier, scopes=["things:create"])(_view)
    rf = RequestFactory()
    assert view.csrf_exempt
    ok = view(rf.post("/", HTTP_AUTHORIZATION=f"Bearer {make(key)}"))
    assert (ok.status_code, ok.content) == (200, b"caller-app")
    missing = view(rf.post("/"))
    assert missing.status_code == 401 and missing["WWW-Authenticate"].startswith("Bearer ")
    assert view(rf.post("/", HTTP_AUTHORIZATION="Basic abc")).status_code == 401
    assert view(rf.post("/", HTTP_AUTHORIZATION=f"Bearer {make(key, aud='x')}")).status_code == 401
    forbidden = view(rf.post("/", HTTP_AUTHORIZATION=f"Bearer {make(key, scope='profile')}"))
    assert forbidden.status_code == 403
    assert json.loads(forbidden.content)["error"] == "insufficient_scope"


def test_decorator_picks_verifier_by_issuer(fetch, verifier, key):
    view = bearer_token_required(lambda iss: verifier if iss == ISSUER else None)(_view)
    rf = RequestFactory()
    assert view(rf.get("/", HTTP_AUTHORIZATION=f"Bearer {make(key)}")).status_code == 200
    other = make(key, iss="https://other.example/realms/X")
    assert view(rf.get("/", HTTP_AUTHORIZATION=f"Bearer {other}")).status_code == 401
