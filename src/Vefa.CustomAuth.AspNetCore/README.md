# Vefa.CustomAuth.AspNetCore

ASP.NET Core endpoint and dependency injection integration for Vefa.CustomAuth.

This package maps OAuth2 and OpenID Connect endpoints and registers the runtime services used by the authorization server.

## Typical Usage

```csharp
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "https://auth.example.com";
    })
    .AddJwtTokenSigning();

app.MapCustomAuthEndpoints();
```

Register a persistence provider separately, such as `Vefa.CustomAuth.EntityFrameworkCore` or `Vefa.CustomAuth.MongoDB`.

## Endpoints

```text
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /connect/authorize
POST /connect/token
GET  /connect/logout
POST /connect/logout
GET  /connect/userinfo
POST /connect/revoke
GET  /login
POST /login
```

## Grant types

The token endpoint dispatches each request to a registered `ICustomAuthGrantHandler`
(`Vefa.CustomAuth.AspNetCore.Endpoints.Grants`) keyed by `grant_type`. Built-in handlers cover:

- `authorization_code` (with PKCE)
- `refresh_token`
- `client_credentials` — confidential machine-to-machine clients. Requires a confidential
  `TokenEndpointAuthMethod` and the per-client opt-in `CustomAuthClient.AllowClientCredentials`.
  Issues an access token only (no ID token, no refresh token), with `sub` set to the client id.

Register an additional `ICustomAuthGrantHandler` to add a custom grant; a registration whose
`GrantType` matches a built-in grant overrides it (last registration wins).

## Security Notes

Keep PKCE enabled, use exact redirect URI matching, and configure HTTPS in production.

Refresh tokens require client refresh-token support and the `offline_access` scope. They are rotated on use, have sliding and absolute expiration, and detect reuse of consumed tokens.

The client credentials grant requires confidential client authentication (`private_key_jwt`); public clients cannot use it.
