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

## Security Notes

Keep PKCE enabled, use exact redirect URI matching, and configure HTTPS in production.

Refresh tokens require client refresh-token support and the `offline_access` scope. They are rotated on use, have sliding and absolute expiration, and detect reuse of consumed tokens.
