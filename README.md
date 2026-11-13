# django-oidc-common

A reusable Django app that provides the Keycloak OIDC plumbing shared by our
Django apps: login session tracking, logout, and OIDC back-channel logout.
With it, a new app chooses how it is reached with one setting, instead of
copying the login and logout code.

## Install

Add it to the app's `requirements.txt`, pinned to a release tag:

```
django-oidc-common @ git+https://github.com/ORG/django-oidc-common.git@v0.1.0
```

This pulls in `Django`, `mozilla-django-oidc`, `PyJWT[crypto]` and `requests`
as dependencies. Pin exact versions of those in the app's own
`requirements.txt` as usual.

`pip` needs `git` on the path to install from a git URL.

### Private repository: installing in Docker

If this repository is private, `pip` needs a GitHub token to clone it. Pass the
token as a BuildKit secret so that it is never written into an image layer:

```dockerfile
RUN --mount=type=secret,id=github_token \
    apt-get update && apt-get install -y --no-install-recommends git \
    && if [ -s /run/secrets/github_token ]; then \
         export GIT_CONFIG_COUNT=1 \
                GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/github_token)@github.com/.insteadOf" \
                GIT_CONFIG_VALUE_0="https://github.com/"; \
       fi \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove git && rm -rf /var/lib/apt/lists/*
```

Build it locally with:

```sh
GITHUB_TOKEN=$(gh auth token) docker build --secret id=github_token,env=GITHUB_TOKEN .
```

With CDK, pass `build_secrets={"github_token": "env=GITHUB_TOKEN"}` to
`DockerImageAsset`. Use a fine-grained token that has read-only **Contents**
access to this repository and nothing else. If the repository is public, leave
the secret out: the `if` skips it and the install works without a token.

## What it provides

- `oidc_common.auth.KeycloakOIDCBackend`: a `mozilla_django_oidc` backend
  that captures the Keycloak session id (`sid`) and subject (`sub`) from the
  ID token at login.
- `oidc_common.models.OIDCSession`: maps that `sid`/`sub` to the local Django
  session it produced, so that a later back-channel logout notification can
  find and end it.
- `oidc_common.middleware.HealthCheckMiddleware`: answers `/healthz/` before
  Django's `ALLOWED_HOSTS` check runs, because an ALB probes a task by its
  private IP rather than by domain name.
- `oidc_common.views` and `oidc_common.urls`: the `logout`, `logged_out` and
  `backchannel_logout` views, mounted at `/logout/`, `/logged-out/` and
  `/oidc/backchannel-logout/`.

An app that uses this package still owns its own `home` view and templates.
The package provides only the OIDC plumbing, not app content.

## Wiring it into an app

```python
# settings.py
INSTALLED_APPS = [
    ...,
    "mozilla_django_oidc",
    "oidc_common",
]
AUTHENTICATION_BACKENDS = (
    "oidc_common.auth.KeycloakOIDCBackend",
    "django.contrib.auth.backends.ModelBackend",
)
MIDDLEWARE = [
    "oidc_common.middleware.HealthCheckMiddleware",  # must be first
    ...,
]
SSO_MODE = "both"  # or "sso_only", which also needs PORTAL_URL
```

```python
# urls.py
urlpatterns = [
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("", include("oidc_common.urls")),
    path("", views.home, name="home"),  # the app's own content
]
```

The `/logged-out/` page extends `base.html` and fills its `title` and
`content` blocks, so the app must provide a `base.html` template.

## `SSO_MODE`: the one decision an app makes

- `SSO_MODE = "sso_only"`: the app is only reached through a portal, and the
  portal decides what a logged-out user sees. `logout()` sends the browser to
  `PORTAL_URL`, which is required in this mode.
- `SSO_MODE = "both"` (the default): the app can also be reached directly,
  with no portal guaranteed to exist. `logout()` sends the browser to this
  package's `/logged-out/` page. That page tries `window.close()`. If the
  browser blocks it, because a script didn't open the tab, the page goes
  back to `document.referrer`. Register `<app>/logged-out/` as a valid post
  logout redirect URI on the Keycloak client.

The back-channel logout receiver (`/oidc/backchannel-logout/`) is always
mounted, whatever the mode. If no other app shares a session with this one,
there is never an `OIDCSession` row for a notification to match, so it does
nothing.

## Settings the app must provide

The package reads these from `django.conf.settings`. Their values are
specific to each app:

| Setting | Notes |
| --- | --- |
| `OIDC_RP_CLIENT_ID`, `OIDC_RP_CLIENT_SECRET` | From the app's Keycloak client |
| `OIDC_RP_SIGN_ALGO` | Normally `"RS256"` |
| `REALM_URL` | For example `f"{KEYCLOAK_BASE_URL}/realms/MYREALM"`. This is the expected `iss` of logout tokens. |
| `OIDC_OP_JWKS_ENDPOINT` | `f"{REALM_URL}/protocol/openid-connect/certs"` |
| `OIDC_OP_LOGOUT_ENDPOINT` | `f"{REALM_URL}/protocol/openid-connect/logout"` |
| `OIDC_VERIFY_SSL` | `True`, except in local development against a self-signed Keycloak |
| `OIDC_STORE_ID_TOKEN = True` | Required, so that `logout()` can send `id_token_hint` |
| `SSO_MODE`, `PORTAL_URL` | See above |

`mozilla_django_oidc` also needs `OIDC_OP_AUTHORIZATION_ENDPOINT`,
`OIDC_OP_TOKEN_ENDPOINT` and `OIDC_OP_USER_ENDPOINT`.

The package does not decide where an app gets `OIDC_RP_CLIENT_ID` and
`OIDC_RP_CLIENT_SECRET` from, such as AWS Secrets Manager or environment
variables. That choice is specific to each app.

## Migrations

The `OIDCSession` migration ships inside this package, so every app that uses
it shares one migration history. The app's normal `python manage.py migrate`
applies it.

If you change `models.py`, generate the migration here, not in a consuming
app:

```sh
DJANGO_SETTINGS_MODULE=tests.settings python -m django makemigrations oidc_common
```

CI fails if `models.py` and the migrations get out of step.

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]" ruff
pytest
ruff check . && ruff format --check .
```

## Releasing

1. Update `version` in `pyproject.toml` and add an entry to `CHANGELOG.md`.
2. Merge to `main`, then tag the release: `git tag v0.2.0 && git push origin v0.2.0`.
   CI checks that the tag matches the version in `pyproject.toml`.
3. In each consuming app, change the `@vX.Y.Z` in `requirements.txt`.

Follow semantic versioning. A change to a model, a URL, or a required setting
is a breaking change for consuming apps.
