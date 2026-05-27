# Vefa.CustomAuth

Vefa.CustomAuth is a lightweight OAuth2 / OpenID Connect SSO library for ASP.NET Core.

The current version is an early reference implementation focused on Authorization Code Flow with PKCE, an SSO session cookie, JWT access tokens, ID tokens, opaque refresh tokens, and JWKS-based signing key discovery.

It is not production-ready yet. The API shape, persistence layer, and security hardening are still evolving.

## Projects

```text
src/
  Vefa.CustomAuth.Core
  Vefa.CustomAuth.AspNetCore
  Vefa.CustomAuth.EntityFrameworkCore
  Vefa.CustomAuth.Tokens
  Vefa.CustomAuth.Server

samples/
  Vefa.CustomAuth.Sample.AuthServer
  Vefa.CustomAuth.Sample.WebApp
  Vefa.CustomAuth.Sample.Api

tests/
  Vefa.CustomAuth.Tests
  Vefa.CustomAuth.AspNetCore.Tests
```

## Current Features

- Authorization Code Flow with PKCE.
- Minimal API endpoint mapping for the auth server.
- OpenID Connect discovery endpoint.
- JWKS endpoint backed by RSA signing keys.
- JWT access token and ID token issuance.
- Opaque refresh token issuance and rotation.
- Hashed authorization code and refresh token storage.
- In-memory stores for samples and tests.
- EF Core `DbContext` and store implementations.

## Supported Endpoints

```text
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /connect/authorize
POST /connect/token
GET  /login
POST /login
```

Logout, userinfo, revoke, introspection, and consent endpoints are planned but not implemented yet.

## Run the Samples

From the repository root:

```bash
./scripts/run-samples.sh
```

This starts all three sample apps:

```text
AuthServer: http://localhost:5175
API:        http://localhost:5098
WebApp:     http://localhost:5043
```

Open the WebApp:

```text
http://localhost:5043
```

Use the sample credentials:

```text
demo / demo
```

Press `Ctrl+C` in the script terminal to stop all sample apps.

## Sample Flow

The sample WebApp uses the standard ASP.NET Core OpenID Connect handler:

1. The WebApp requires login.
2. The WebApp redirects to the AuthServer.
3. The AuthServer authenticates the sample user.
4. The AuthServer redirects back with an authorization code.
5. The WebApp exchanges the code for tokens.
6. The WebApp calls the protected API with the access token.
7. The API validates the JWT access token with `JwtBearer`.

## Minimal Auth Server Setup

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5175";
        options.RequireHttps = false;
    })
    .AddJwtTokenSigning()
    .AddInMemoryStores(stores =>
    {
        stores.Clients.Add(new CustomAuthClient
        {
            ClientId = "sample-webapp",
            DisplayName = "Sample Web App",
            RedirectUris = { "http://localhost:5043/signin-oidc" },
            AllowedScopes = { "openid", "profile", "email", "offline_access", "sample-api" },
        });
    });

app.MapVefaCustomAuthEndpoints();
```

`RequireHttps = false` is only for the local HTTP sample.

## Build and Test

```bash
dotnet build --no-restore -p:UseSharedCompilation=false -nr:false -v:minimal
dotnet test --no-build -v:minimal
```

## Status

This repository is still in active development. The current implementation is useful for validating the package design and sample SSO flow, but it still needs options validation, broader host scenarios, and production hardening before publishing.
