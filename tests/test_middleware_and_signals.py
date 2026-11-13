from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.test import RequestFactory

from oidc_common.auth import KeycloakOIDCBackend
from oidc_common.models import OIDCSession


def test_healthcheck_bypasses_allowed_hosts(client):
    # The ALB probes by private IP, which isn't in ALLOWED_HOSTS.
    response = client.get("/healthz/", HTTP_HOST="10.0.1.23")
    assert response.status_code == 200
    assert response.content == b"OK"


def test_other_paths_still_check_allowed_hosts(client):
    assert client.get("/logged-out/", HTTP_HOST="10.0.1.23").status_code == 400


def _request_with_session():
    from django.contrib.sessions.backends.db import SessionStore

    request = RequestFactory().get("/")
    request.session = SessionStore()
    return request


def test_backend_stashes_sid_and_sub():
    request = _request_with_session()
    backend = KeycloakOIDCBackend()
    backend.request = request

    with mock.patch(
        "mozilla_django_oidc.auth.OIDCAuthenticationBackend.get_or_create_user",
        return_value="user",
    ) as parent:
        result = backend.get_or_create_user("at", "it", {"sid": "s1", "sub": "u1"})

    assert result == "user"
    parent.assert_called_once()
    assert request.session["oidc_sid"] == "s1"
    assert request.session["oidc_sub"] == "u1"


@pytest.mark.django_db
def test_login_records_oidc_session():
    request = _request_with_session()
    request.session["oidc_sid"] = "s1"
    request.session["oidc_sub"] = "u1"
    request.session.create()
    user = get_user_model().objects.create_user("bob")

    user_logged_in.send(sender=type(user), request=request, user=user)

    row = OIDCSession.objects.get()
    assert (row.sid, row.sub, row.session_key) == (
        "s1",
        "u1",
        request.session.session_key,
    )
    assert "oidc_sid" not in request.session


@pytest.mark.django_db
def test_non_oidc_login_records_nothing():
    request = _request_with_session()
    request.session.create()
    user = get_user_model().objects.create_user("carol")

    user_logged_in.send(sender=type(user), request=request, user=user)

    assert not OIDCSession.objects.exists()
