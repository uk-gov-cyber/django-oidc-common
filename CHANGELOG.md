# Changelog

## 0.2.0

- New `oidc_common.bearer`: `BearerTokenVerifier` and the
  `bearer_token_required` view decorator, for apps that expose an API to other
  apps. Checks the signature (JWKS, refetched once on an unknown key id), the
  exact issuer, the audience, `exp`/`iat`, `typ: Bearer` and required scopes.
  It reads no settings, so an app serving several realms can use one verifier
  per realm. Nothing else changed; no migrations.

## 0.1.0

First packaged release. Code is unchanged from the copies previously vendored
as `shared/oidc_common` in code-frontend and `cdk/shared/oidc_common` in
the keycloak code. The migration history is the same, so an existing database
needs no changes.
