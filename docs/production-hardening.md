# Production Hardening Checklist

Use this checklist before publishing or deploying a Vefa.CustomAuth server outside local development.

## Transport and Issuer

- Use HTTPS for the public issuer URI.
- Keep `CustomAuthOptions.RequireHttps` enabled outside local development.
- Configure the issuer URI to exactly match the externally reachable auth server origin.
- Validate reverse proxy forwarded headers before relying on generated URLs.

## Cookies

- Use a host-specific session cookie name when multiple auth servers share a parent domain.
- Keep the SSO cookie `HttpOnly`.
- Keep the SSO cookie `Secure` in production.
- Keep `SameSite=Lax` unless a documented cross-site scenario requires a different value.
- Set session lifetimes deliberately and align cleanup behavior with those lifetimes.

## Tokens

- Keep authorization code lifetimes short, preferably 60 to 120 seconds.
- Keep authorization codes and refresh tokens stored only as hashes.
- Use opaque refresh tokens and rotate them on every use.
- Keep refresh token reuse detection enabled.
- Treat reuse of a consumed refresh token as a suspicious event and review the related audit log.
- Configure both sliding and absolute refresh token lifetimes.
- Keep access token lifetimes short enough for the protected API risk profile.
- Validate issuer, audience, signature, and token lifetime in every protected API.

## Signing Keys

- Persist signing keys in a durable provider, not in-memory storage.
- Protect private key material with database encryption, envelope encryption, or a managed secret store.
- Rotate signing keys on a documented schedule.
- Keep retired public keys available until all tokens signed by those keys have expired.
- Never expose private key material through Admin UI, logs, API responses, or diagnostics.

## Persistence

- Use EF Core or MongoDB persistent stores in production.
- Do not rely on in-memory stores for clients, tokens, sessions, signing keys, or audit logs.
- Verify database indexes for clients, codes, refresh tokens, sessions, signing keys, scopes, and audit logs.
- Run cleanup jobs for expired authorization codes, refresh tokens, and sessions.
- Back up persistent stores according to the host application's recovery objective.

## Admin UI

- Do not expose the Admin UI anonymously.
- Require host application authorization on `MapCustomAuthAdminUI`.
- Restrict Admin UI access to a small operational role.
- Put the Admin UI behind network controls when possible.
- Review audit logs after client, scope, session, refresh token, or signing key changes.

## Clients and Redirects

- Register only exact redirect URIs.
- Avoid wildcard, prefix, or user-controlled redirect matching.
- Review post-logout redirect URIs with the same strictness as login redirect URIs.
- Enable refresh tokens only for clients that are allowed to request `offline_access`.
- Keep PKCE required unless there is a documented confidential-client reason to change it.
- Remove unused clients and scopes.

## Observability

- Log security-relevant events without secrets, raw tokens, authorization codes, passwords, or PII.
- Monitor failed token exchanges, invalid redirect attempts, revoked token use, and refresh token reuse.
- Alert on unexpected signing key changes.
- Keep audit logs in durable storage.

## Package and Deployment

- Pin package versions.
- Run `dotnet build` and the full test suite in CI.
- Pack in Release mode before publishing packages.
- Publish only packages that are intended to be part of the supported public API.
