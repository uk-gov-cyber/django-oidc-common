import jwt
import requests
from django.conf import settings

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

_jwks_cache = None


class InvalidLogoutToken(Exception):
    pass


def _get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        resp = requests.get(
            settings.OIDC_OP_JWKS_ENDPOINT,
            verify=settings.OIDC_VERIFY_SSL,
            timeout=10,
        )
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache


def _get_public_key(token):
    header = jwt.get_unverified_header(token)
    for key in _get_jwks()["keys"]:
        if key["kid"] == header["kid"]:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key)
    raise InvalidLogoutToken("signing key not found in JWKS")


def verify_logout_token(token):
    """
    Verifies a Keycloak back-channel logout_token per the OIDC Back-Channel
    Logout 1.0 spec: valid signature, matching issuer/audience, a
    backchannel-logout event claim, no nonce claim, and a sub and/or sid.
    """
    try:
        public_key = _get_public_key(token)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[settings.OIDC_RP_SIGN_ALGO],
            audience=settings.OIDC_RP_CLIENT_ID,
            issuer=settings.REALM_URL,
        )
    except jwt.PyJWTError as exc:
        raise InvalidLogoutToken(str(exc)) from exc

    if BACKCHANNEL_LOGOUT_EVENT not in payload.get("events", {}):
        raise InvalidLogoutToken("missing backchannel-logout event claim")
    if "nonce" in payload:
        raise InvalidLogoutToken("logout_token must not contain a nonce")
    if not payload.get("sid") and not payload.get("sub"):
        raise InvalidLogoutToken("logout_token must contain sub and/or sid")

    return payload
