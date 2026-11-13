from django.db import models


class OIDCSession(models.Model):
    """
    Maps a Keycloak SSO session (sid) and subject (sub), captured when the
    OIDC login completes, onto the local Django session it produced - so a
    Keycloak back-channel logout notification for that sid/sub can find and
    end the matching local session. Harmless if the app is never reached via
    a flow that shares sessions with anything else - there's simply nothing
    else to notify.
    """

    sid = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    sub = models.CharField(max_length=255, db_index=True)
    session_key = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)
