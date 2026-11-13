from django.urls import path

from . import views

urlpatterns = [
    path("logout/", views.logout, name="logout"),
    path("logged-out/", views.logged_out, name="logged_out"),
    path(
        "oidc/backchannel-logout/", views.backchannel_logout, name="backchannel_logout"
    ),
]
