# Vefa.CustomAuth

Vefa.CustomAuth is a lightweight OAuth2 / OpenID Connect SSO library for ASP.NET Core.

The current version is an early reference implementation focused on Authorization Code Flow with PKCE, an SSO session cookie, JWT access tokens, ID tokens, opaque refresh tokens, JWKS-based signing key discovery, provider-backed persistence, and an embedded Admin UI.

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
- Sliding and absolute refresh token expiration.
- Refresh token session binding and reuse detection.
- Hashed authorization code and refresh token storage.
- In-memory stores for tests and simple local scenarios.
- EF Core `DbContext` and store implementations.
- MongoDB store implementations.
- Embedded Admin UI for clients, scopes, sessions, refresh tokens, signing keys, and audit logs.

## Supported Endpoints

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

Introspection and consent endpoints are deferred beyond the current SSO-focused scope unless explicitly prioritized.

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

The AuthServer sample uses SQLite-backed EF stores for clients, authorization codes, refresh tokens, sessions, and signing keys. The demo user store is still in-memory because user persistence is intentionally owned by the host application.

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

## EF Core Store Setup

```csharp
builder.Services.AddVefaCustomAuthEntityFrameworkCore(options =>
{
    options.UseSqlite(connectionString);
});
```

For applications that own their own `DbContext`, register the CustomAuth model configuration on that context and then register the stores:

```csharp
builder.Services.AddVefaCustomAuthStores<AppDbContext>();
```

## MongoDB Store Setup

```csharp
builder.Services.AddVefaCustomAuthMongoDbStores(options =>
{
    options.ConnectionString = connectionString;
    options.DatabaseName = "customauth";
});
```

## Admin UI

```csharp
app.MapVefaCustomAuthAdminUI("/customauth")
    .RequireAuthorization();
```

The Admin UI is optional. In production, protect it with host application authorization.

## Refresh Token Lifecycle

Refresh tokens are opaque values stored only as hashes. Each refresh token belongs to a client, user, and SSO session when a session is available.

Refresh token rotation is enabled by default: using a refresh token consumes it and issues a replacement token. The replacement token keeps the original token chain's absolute expiration and records the consumed token as its parent.

`RefreshTokenLifetime` controls the sliding lifetime. `RefreshTokenAbsoluteLifetime` controls the maximum lifetime of the token chain. Client-level `RefreshTokenLifetimeSeconds` and `RefreshTokenAbsoluteLifetimeSeconds` override the global options when set.

If a consumed refresh token is used again, Vefa.CustomAuth records `RefreshTokenReuseDetected` and revokes the session-bound refresh token chain when possible.

## Production Hardening

Before using Vefa.CustomAuth outside local development, review the [production hardening checklist](docs/production-hardening.md).

## Build and Test

```bash
dotnet build --no-restore -p:UseSharedCompilation=false -nr:false -v:minimal
dotnet test --no-build -v:minimal
```

## Pack Packages

Create all NuGet packages with an explicit version:

```bash
scripts/pack-all-packages.sh 1.0.0
```

By default, packages are written to `artifacts/packages`. To use a custom output directory:

```bash
scripts/pack-all-packages.sh 1.0.0 ./artifacts
```

Push packages to NuGet.org:

```bash
export NUGET_API_KEY="your-api-key"

dotnet nuget push "artifacts/*.nupkg" \
  --api-key "$NUGET_API_KEY" \
  --source https://api.nuget.org/v3/index.json \
  --skip-duplicate
```

## Status

This repository is still in active development. The current implementation is useful for validating the package design and sample SSO flow, but it still needs public API stabilization, documentation, and production hardening before publishing.
