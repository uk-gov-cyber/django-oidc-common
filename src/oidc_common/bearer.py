"""
Bearer access tokens for apps that expose an API to other apps.

The calling app gets an access token from Keycloak (usually with the client
credentials grant) and sends it as `Authorization: Bearer <token>`. This
module checks it properly before the view runs:

- signature, against the realm's JWKS (refetched once if a new key id
  appears, so key rotation works without a restart);
- `iss` is exactly the expected issuer, `aud` contains the expected audience,
  and `exp`/`iat` are present and valid;
- `typ` is `Bearer`, so an ID token, refresh token or logout token is refused
  even though Keycloak signs them with the same key;
- every required scope is in the token's `scope` claim.

No Django settings are read here: the app builds a `BearerTokenVerifier` for
each issuer it accepts and passes it to `bearer_token_required`.

    verifier = BearerTokenVerifier(issuer="https://kc.example/realms/GCU", audience="my-api")

    @bearer_token_required(verifier, scopes=["things:create"])
    def create_thing(request):
        caller = request.bearer_claims["azp"]   # the calling client
        ...

The audience is not added by Keycloak by default. Give the calling client an
Audience mapper (usually on the client scope that carries the required scope)
whose "Included client audience" is the API's own client.
"""

import threading
import time
from functools import wraps

import jwt
import requests
from django.http import JsonResponse


class InvalidBearerToken(Exception):
    """The token is missing, malformed, unsigned by the issuer, expired or for someone else (HTTP 401)."""


class InsufficientScope(InvalidBearerToken):
    """The token is valid but lacks a required scope (HTTP 403)."""


class BearerTokenVerifier:
    """Verifies access tokens from one issuer, for one audience."""

    # Minimum seconds between JWKS refetches triggered by an unknown key id,
    # so tokens with made-up key ids can't make us hammer Keycloak.
    REFRESH_COOLDOWN = 60

    def __init__(
        self,
        issuer,
        audience,
        *,
        jwks_url=None,
        algorithms=("RS256",),
        verify_ssl=True,
        leeway=0,
        jwks_ttl=3600,
        timeout=10,
    ):
        if not issuer or not audience:
            raise ValueError("issuer and audience are both required")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url or f"{self.issuer}/protocol/openid-connect/certs"
        self.algorithms = list(algorithms)
        self.verify_ssl = verify_ssl
        self.leeway = leeway
        self.jwks_ttl = jwks_ttl
        self.timeout = timeout
        self._lock = threading.Lock()
        self._keys = {}
        self._fetched_at = 0.0

    def _fetch(self):
        resp = requests.get(self.jwks_url, verify=self.verify_ssl, timeout=self.timeout)
        resp.raise_for_status()
        keys = {}
        for jwk in resp.json().get("keys", []):
            if jwk.get("kid") and jwk.get("use", "sig") == "sig":
                keys[jwk["kid"]] = jwk
        self._keys = keys
        self._fetched_at = time.monotonic()

    def _key(self, kid):
        with self._lock:
            age = time.monotonic() - self._fetched_at
            if (
                not self._keys
                or age > self.jwks_ttl
                or (kid not in self._keys and age > self.REFRESH_COOLDOWN)
            ):
                try:
                    self._fetch()
                except (requests.RequestException, ValueError) as exc:
                    if not self._keys:
                        raise InvalidBearerToken(
                            "could not fetch the issuer's signing keys"
                        ) from exc
            jwk = self._keys.get(kid)
        if jwk is None:
            raise InvalidBearerToken("token signed with an unknown key")
        return jwt.PyJWK(jwk).key

    def verify(self, token, scopes=()):
        """The token's claims if it's valid and has every scope in `scopes`."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidBearerToken("malformed token") from exc
        if header.get("alg") not in self.algorithms:
            raise InvalidBearerToken("token signed with an unexpected algorithm")
        key = self._key(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidBearerToken(str(exc)) from exc
        if claims.get("typ") != "Bearer":
            raise InvalidBearerToken("not an access token")
        granted = set(str(claims.get("scope", "")).split())
        missing = sorted(set(scopes) - granted)
        if missing:
            raise InsufficientScope(f"missing scope: {' '.join(missing)}")
        return claims


def unverified_issuer(token):
    """The token's `iss`, unverified - only for choosing which verifier to use."""
    try:
        return jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError:
        return None


def _error(status, code, description, scopes=()):
    challenge = f'Bearer error="{code}", error_description="{description}"'
    if scopes:
        challenge += f', scope="{" ".join(scopes)}"'
    response = JsonResponse(
        {"error": code, "error_description": description}, status=status
    )
    response["WWW-Authenticate"] = challenge
    response["Cache-Control"] = "no-store"
    return response


def bearer_token_required(verifier, scopes=()):
    """
    View decorator: the request must carry a valid bearer token with `scopes`.
    The claims are put on `request.bearer_claims`.

    `verifier` is a BearerTokenVerifier, or a callable taking the token's
    (unverified) issuer and returning the verifier for it, or None if that
    issuer isn't accepted - for apps serving several realms. Either way the
    chosen verifier then checks the issuer exactly.

    The view is CSRF-exempt: it's authenticated by the Authorization header,
    never by cookies, so a browser can't be tricked into sending it.
    """
    scopes = tuple(scopes)

    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            scheme, _, token = request.headers.get("Authorization", "").partition(" ")
            token = token.strip()
            if scheme.lower() != "bearer" or not token:
                return _error(
                    401, "invalid_request", "a bearer token is required", scopes
                )
            chosen = verifier
            if not isinstance(verifier, BearerTokenVerifier):
                chosen = verifier(unverified_issuer(token))
                if chosen is None:
                    return _error(
                        401, "invalid_token", "token issuer not accepted", scopes
                    )
            try:
                request.bearer_claims = chosen.verify(token, scopes)
            except InsufficientScope as exc:
                return _error(403, "insufficient_scope", str(exc), scopes)
            except InvalidBearerToken as exc:
                return _error(401, "invalid_token", str(exc), scopes)
            return view(request, *args, **kwargs)

        wrapped.csrf_exempt = True
        return wrapped

    return decorator
