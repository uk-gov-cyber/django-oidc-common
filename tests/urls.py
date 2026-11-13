from django.urls import include, path

urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("", include("oidc_common.urls")),
]
