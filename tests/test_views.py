from urllib.parse import parse_qs, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import ImproperlyConfigured

from oidc_common.models import OIDCSession

pytestmark = pytest.mark.django_db


def _logout_redirect_params(response):
    assert response.status_code == 302
    location = urlparse(response["Location"])
    assert location._replace(query="").geturl() == settings.OIDC_OP_LOGOUT_ENDPOINT
    return parse_qs(location.query)


def test_logout_both_mode_returns_to_logged_out_page(client):
    session = client.session
    session["oidc_id_token"] = "the-id-token"
    session.save()

    params = _logout_redirect_params(client.get("/logout/"))

    assert params["post_logout_redirect_uri"] == ["http://testserver/logged-out/"]
    assert params["id_token_hint"] == ["the-id-token"]


def test_logout_without_id_token_omits_hint(client):
    params = _logout_redirect_params(client.get("/logout/"))
    assert "id_token_hint" not in params


def test_logout_sso_only_mode_returns_to_portal(client, settings):
    settings.SSO_MODE = "sso_only"
    settings.PORTAL_URL = "https://portal.example.test/"

    params = _logout_redirect_params(client.get("/logout/"))

    assert params["post_logout_redirect_uri"] == ["https://portal.example.test/"]


def test_logout_sso_only_mode_requires_portal_url(client, settings):
    settings.SSO_MODE = "sso_only"
    settings.PORTAL_URL = None
    with pytest.raises(ImproperlyConfigured, match="PORTAL_URL"):
        client.get("/logout/")


def test_logout_rejects_unknown_mode(client, settings):
    settings.SSO_MODE = "sometimes"
    with pytest.raises(ImproperlyConfigured, match="SSO_MODE"):
        client.get("/logout/")


def test_logout_ends_local_session(client):
    user = get_user_model().objects.create_user("alice")
    client.force_login(user)
    client.get("/logout/")
    assert "_auth_user_id" not in client.session


def test_logged_out_page_renders(client):
    response = client.get("/logged-out/")
    assert response.status_code == 200
    assert b"Signed out" in response.content


def _local_session():
    store = SessionStore()
    store["marker"] = True
    store.create()
    return store.session_key


def test_backchannel_logout_by_sid_ends_only_that_session(client, make_logout_token):
    target = _local_session()
    other = _local_session()
    OIDCSession.objects.create(sid="kc-session-1", sub="user-1", session_key=target)
    OIDCSession.objects.create(sid="kc-session-2", sub="user-1", session_key=other)

    response = client.post(
        "/oidc/backchannel-logout/", {"logout_token": make_logout_token()}
    )

    assert response.status_code == 200
    assert not SessionStore().exists(target)
    assert SessionStore().exists(other)
    assert list(OIDCSession.objects.values_list("sid", flat=True)) == ["kc-session-2"]


def test_backchannel_logout_by_sub_ends_all_user_sessions(client, make_logout_token):
    keys = [_local_session(), _local_session()]
    for i, key in enumerate(keys):
        OIDCSession.objects.create(sid=f"kc-{i}", sub="user-1", session_key=key)

    response = client.post(
        "/oidc/backchannel-logout/", {"logout_token": make_logout_token(sid=None)}
    )

    assert response.status_code == 200
    assert not any(SessionStore().exists(k) for k in keys)
    assert not OIDCSession.objects.exists()


def test_backchannel_logout_needs_no_csrf_token(make_logout_token):
    from django.test import Client

    response = Client(enforce_csrf_checks=True).post(
        "/oidc/backchannel-logout/", {"logout_token": make_logout_token()}
    )
    assert response.status_code == 200


def test_backchannel_logout_missing_token(client):
    assert client.post("/oidc/backchannel-logout/").status_code == 400


def test_backchannel_logout_invalid_token(client, make_logout_token):
    token = make_logout_token(aud="someone-else")
    response = client.post("/oidc/backchannel-logout/", {"logout_token": token})
    assert response.status_code == 400


def test_backchannel_logout_rejects_get(client):
    assert client.get("/oidc/backchannel-logout/").status_code == 405
