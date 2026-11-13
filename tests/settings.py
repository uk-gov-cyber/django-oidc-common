from pathlib import Path

SECRET_KEY = "test-only"
DEBUG = False
ALLOWED_HOSTS = ["testserver"]
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "mozilla_django_oidc",
    "oidc_common",
]

MIDDLEWARE = [
    "oidc_common.middleware.HealthCheckMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

AUTHENTICATION_BACKENDS = (
    "oidc_common.auth.KeycloakOIDCBackend",
    "django.contrib.auth.backends.ModelBackend",
)

ROOT_URLCONF = "tests.urls"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
SESSION_ENGINE = "django.contrib.sessions.backends.db"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Supplies the base.html that oidc_common/logged_out.html extends -
        # a consuming app provides its own.
        "DIRS": [Path(__file__).parent / "templates"],
        "APP_DIRS": True,
    }
]

REALM_URL = "https://keycloak.example.test/realms/TEST"
OIDC_RP_CLIENT_ID = "test-client"
OIDC_RP_CLIENT_SECRET = "test-secret"
OIDC_RP_SIGN_ALGO = "RS256"
OIDC_OP_AUTHORIZATION_ENDPOINT = f"{REALM_URL}/protocol/openid-connect/auth"
OIDC_OP_TOKEN_ENDPOINT = f"{REALM_URL}/protocol/openid-connect/token"
OIDC_OP_USER_ENDPOINT = f"{REALM_URL}/protocol/openid-connect/userinfo"
OIDC_OP_JWKS_ENDPOINT = f"{REALM_URL}/protocol/openid-connect/certs"
OIDC_OP_LOGOUT_ENDPOINT = f"{REALM_URL}/protocol/openid-connect/logout"
OIDC_VERIFY_SSL = True
OIDC_STORE_ID_TOKEN = True

SSO_MODE = "both"
