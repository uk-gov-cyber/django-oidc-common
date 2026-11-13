from mozilla_django_oidc.auth import OIDCAuthenticationBackend


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    """
    Stashes the Keycloak session id (sid) and subject (sub) claims from the
    ID token onto the request session before the user is logged in, so the
    user_logged_in signal receiver (see signals.py) can record which local
    Django session belongs to which Keycloak SSO session. That mapping is
    what lets a later back-channel logout notification find and end it.
    """

    def get_or_create_user(self, access_token, id_token, payload):
        self.request.session["oidc_sid"] = payload.get("sid")
        self.request.session["oidc_sub"] = payload.get("sub")
        return super().get_or_create_user(access_token, id_token, payload)
