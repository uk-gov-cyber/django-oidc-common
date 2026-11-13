import urllib.parse

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .backchannel import InvalidLogoutToken, verify_logout_token
from .models import OIDCSession

SSO_ONLY = "sso_only"
BOTH = "both"
VALID_SSO_MODES = (SSO_ONLY, BOTH)


def _post_logout_redirect_uri(request):
    """
    Where Keycloak sends the browser once it's ended the SSO session -
    decided by the one setting (SSO_MODE) each app's designer picks:

      - "sso_only": this app is only ever meant to be reached via a portal
        (or similar) that owns the "what to show a logged-out user" UX -
        send the browser back there (PORTAL_URL).
      - "both": this app is also reached directly, with no such portal
        guaranteed to exist - land on this app's own arrival-agnostic
        logged_out page instead (see logged_out() below).
    """
    mode = getattr(settings, "SSO_MODE", BOTH)
    if mode not in VALID_SSO_MODES:
        raise ImproperlyConfigured(
            f"SSO_MODE must be one of {VALID_SSO_MODES!r}, got {mode!r}"
        )

    if mode == SSO_ONLY:
        portal_url = getattr(settings, "PORTAL_URL", None)
        if not portal_url:
            raise ImproperlyConfigured(
                "SSO_MODE is 'sso_only' but PORTAL_URL is not set - there's "
                "nowhere to send the browser after logout."
            )
        return portal_url

    return request.build_absolute_uri(reverse("logged_out"))


def logout(request):
    # Grab the id_token before flushing the session - Keycloak needs it
    # (id_token_hint) to know which SSO session to end.
    id_token = request.session.get("oidc_id_token")

    auth_logout(request)

    params = {"post_logout_redirect_uri": _post_logout_redirect_uri(request)}
    if id_token:
        params["id_token_hint"] = id_token

    return redirect(
        f"{settings.OIDC_OP_LOGOUT_ENDPOINT}?{urllib.parse.urlencode(params)}"
    )


def logged_out(request):
    """
    Only ever reached when SSO_MODE == "both" - the dedicated "Valid post
    logout redirect URI" to register on the client. Not login_required:
    there's no session left to check by the time we land here. It just
    tries to tidy up the browser tab via JS rather than showing an app page.
    """
    # Namespaced under templates/oidc_common/ so it can't be shadowed by (or
    # accidentally shadow) an app's own top-level templates dir.
    return render(request, "oidc_common/logged_out.html")


@csrf_exempt
@require_POST
def backchannel_logout(request):
    """
    Called directly by Keycloak (server-to-server, no browser involved) when
    an SSO session ends. If this app has no OIDCSession row for the sid/sub
    in the token - e.g. it was never reached via anything else sharing that
    session - there's simply nothing to end here.
    """
    token = request.POST.get("logout_token")
    if not token:
        return HttpResponseBadRequest("missing logout_token")

    try:
        payload = verify_logout_token(token)
    except InvalidLogoutToken:
        return HttpResponseBadRequest("invalid logout_token")

    sid = payload.get("sid")
    sub = payload.get("sub")
    sessions = (
        OIDCSession.objects.filter(sid=sid)
        if sid
        else OIDCSession.objects.filter(sub=sub)
    )

    for oidc_session in sessions:
        SessionStore(session_key=oidc_session.session_key).delete()
    sessions.delete()

    return HttpResponse(status=200)
