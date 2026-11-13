import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from oidc_common.backchannel import InvalidLogoutToken, verify_logout_token


def test_valid_token(make_logout_token):
    payload = verify_logout_token(make_logout_token())
    assert payload["sid"] == "kc-session-1"
    assert payload["sub"] == "user-1"


def test_sub_only_is_accepted(make_logout_token):
    assert verify_logout_token(make_logout_token(sid=None))["sub"] == "user-1"


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"iss": "https://evil.example/realms/TEST"}, "issuer"),
        ({"aud": "some-other-client"}, "audience"),
        ({"events": {}}, "backchannel-logout event"),
        ({"nonce": "abc"}, "nonce"),
        ({"sid": None, "sub": None}, "sub and/or sid"),
        ({"kid": "unknown-key"}, "signing key not found"),
    ],
)
def test_rejected_tokens(make_logout_token, overrides, reason):
    with pytest.raises(InvalidLogoutToken, match=f"(?i){reason.split()[0]}"):
        verify_logout_token(make_logout_token(**overrides))


def test_wrong_signing_key_is_rejected(make_logout_token):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(InvalidLogoutToken):
        verify_logout_token(make_logout_token(key=other_key))
