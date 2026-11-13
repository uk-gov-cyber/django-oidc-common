from .models import OIDCSession


def record_oidc_session(sender, request, user, **kwargs):
    """Persists the sid/sub -> session_key mapping set by KeycloakOIDCBackend."""
    sid = request.session.pop("oidc_sid", None)
    sub = request.session.pop("oidc_sub", None)
    if not sub:
        return
    OIDCSession.objects.create(
        sid=sid, sub=sub, session_key=request.session.session_key
    )
