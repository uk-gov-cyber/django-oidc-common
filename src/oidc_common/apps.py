from django.apps import AppConfig


class OidcCommonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "oidc_common"

    def ready(self):
        from django.contrib.auth.signals import user_logged_in

        from . import signals

        user_logged_in.connect(signals.record_oidc_session)
