# Sample Auth Server — configuration guide

This sample is a runnable Vefa.CustomAuth authorization server. It demonstrates how a host wires the
library together and which knobs are available. Everything here is configured in
[`Program.cs`](Program.cs); this document explains each setting and how to change it.

## Run it

```bash
dotnet run --project samples/Vefa.CustomAuth.Sample.AuthServer
# or, with the other samples:
./scripts/run-samples.sh
```

- Auth server: `http://localhost:5175` (issuer; set in `launchSettings.json`)
- Discovery: `http://localhost:5175/.well-known/openid-configuration`
- Admin UI: `http://localhost:5175/customauth/`
- Sign in with `demo` / `demo`.

## Core options (`AddCustomAuth`)

```csharp
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "http://localhost:5175"; // MUST match the public URL / launch profile
        options.RequireHttps = false;             // dev only — set true in production
    })
    .AddJwtTokenSigning();                         // RSA signing key, bootstrapped on first use
```

Other useful `CustomAuthOptions` (defaults shown):

| Option | Default | Purpose |
| --- | --- | --- |
| `Issuer` | — (required) | Token `iss` and discovery base URL. |
| `RequireHttps` | `true` | Enforce HTTPS; also drives `__Host-` session cookie prefix. |
| `LoginPath` | `/login` | Host login page; the library only handles `POST /login`. |
| `LogoutPath` | `/logout` | Host logout page. |
| `PostLogoutRedirectUri` | `/` | Fallback redirect after logout. |
| `AuthorizationCodeLifetime` | 60s | Single-use code lifetime. |
| `AccessTokenLifetime` | 1h | Access token lifetime. |
| `RefreshTokenLifetime` | 30d | Sliding refresh lifetime. |
| `RefreshTokenAbsoluteLifetime` | 30d | Max refresh chain lifetime. |
| `DetectRefreshTokenReuse` | `true` | Revoke the chain on reuse. |
| `ClientAssertionClockSkew` | 60s | `exp`/`nbf` tolerance for `private_key_jwt` assertions. |

## User store: in-memory vs ASP.NET Core Identity

Controlled by the `UseAspNetCoreIdentity` configuration key (defaults to `true`). Both expose the same
`ICustomAuthUserStore` to the library, so the protocol is identical either way.

```jsonc
// appsettings.json
"UseAspNetCoreIdentity": true   // false => simple in-memory demo store
```

- **`true`** — `SampleIdentityDbContext` (its own SQLite db `identity-sample.db`), seeded with the
  `demo` user (roles + claims) by `IdentitySeeder`. Password policy is relaxed so `demo` works; tighten
  for production. See `Identity/IdentityUserStore.cs`.
- **`false`** — `InMemoryUserStore` seeded inline in `Program.cs` with custom claims.

## Persistence (EF Core / SQLite)

Protocol data (clients, codes, tokens, signing keys, sessions, scopes, and audit logs) uses EF Core + SQLite. This sample uses a derived `SampleCustomAuthDbContext` so the generated table names stay short and sample-friendly:

```csharp
builder.Services.AddDbContext<SampleCustomAuthDbContext>(o =>
    o.UseSqlite("Data Source=customauth-sample.db"));
builder.Services.AddCustomAuthStores<SampleCustomAuthDbContext>();
```

`DatabaseSeeder` calls `EnsureCreatedAsync` and seeds the demo clients. The `.db` files are generated
at runtime and are git-ignored. Client redirect URIs, post-logout redirect URIs, and allowed scopes
are stored as one-to-many child rows, not as newline-delimited columns.

The sample protocol database uses these table names:

| Table | Purpose |
| --- | --- |
| `Clients` | Registered OAuth/OIDC clients. |
| `ClientRedirectUris` | Allowed authorization redirect URIs per client. |
| `ClientPostLogoutRedirectUris` | Allowed post-logout redirect URIs per client. |
| `ClientAllowedScopes` | Scopes each client may request. |
| `AuthorizationCodes` | Hashed, single-use authorization codes. |
| `RefreshTokens` | Hashed refresh tokens and token-chain metadata. |
| `Sessions` | SSO session records. |
| `SigningKeys` | JWT signing keys. |
| `Scopes` | Available OAuth/OIDC scopes. |
| `AuditLogs` | Administrative and security audit events. |

If you already have an older sample database, the seeder creates the new client relation tables when
possible. For unrelated schema experiments, deleting `customauth-sample.db` is still the simplest way
to recreate the demo database from scratch.

Swap SQLite for SQL Server / PostgreSQL by changing the `UseSqlite(...)` call.

## Signing key

The sample chooses its signing key at startup: **if `Keys/signing.pfx` exists, it signs with that
certificate** (`AddSigningCertificate`); otherwise it falls back to the auto-generated key in the
signing key store (`AddJwtTokenSigning`).

```csharp
var customAuthBuilder = builder.Services.AddCustomAuth(/* ... */).AddJwtTokenSigning();

var signingCertificatePath = Path.Combine(builder.Environment.ContentRootPath, "Keys", "signing.pfx");
if (File.Exists(signingCertificatePath))
{
    customAuthBuilder.AddSigningCertificate(
        signingCertificatePath,
        builder.Configuration["SigningCertificate:Password"]);
}
```

`signing.pfx` is **git-ignored** (it holds a private key), so a fresh clone uses the store-backed key.
The dev password lives in `appsettings.Development.json`. To try the certificate path, generate a PFX
as described in [`Keys/README.md`](Keys/README.md). Using the same certificate on every instance keeps
the JWKS consistent across a load-balanced farm. See the
[production hardening guide](../../docs/production-hardening.md#choosing-the-signing-key-source).

## Seeded clients

`DatabaseSeeder` registers three clients:

| Client | Auth method | Notes |
| --- | --- | --- |
| `sample-webapp` | public (PKCE) | The Sample.WebApp relying party. |
| `swagger-ui` | public (PKCE) | Swagger UI in Sample.Api. |
| `service-client` | `private_key_jwt` | Confidential client; see below. |

## Admin UI

The sample maps the embedded Admin UI at:

```text
http://localhost:5175/customauth/
```

Because this sample auth server does not have a separate ASP.NET Core dashboard-user cookie, the Admin
UI is configured with `AllowAnonymous = true` for local development only:

```csharp
app.MapCustomAuthAdminUI(options =>
{
    options.PathPrefix = "/customauth";
    options.AllowAnonymous = true;
});
```

Do not copy that anonymous setting into production. Protect the route with host application
authorization or network controls.

## Confidential client (`private_key_jwt`)

`service-client` authenticates with a signed JWT assertion. Its **public** JWKS lives in
[`Keys/service-client.jwks.json`](Keys/service-client.jwks.json) and is loaded by `DatabaseSeeder`. The
matching private key is never shipped. To generate your own key pair and see the end-to-end signing
flow, read [`Keys/README.md`](Keys/README.md) and [`docs/private-key-jwt.md`](../../docs/private-key-jwt.md).

Set this on any client to require it:

```csharp
TokenEndpointAuthMethod = CustomAuthClientAuthenticationMethod.PrivateKeyJwt,
JwksJson = "<public JWKS json>",
```

## Custom claims (profile service)

`MyProfileService` (`ICustomAuthProfileService`) injects claims into issued tokens. It reads the user's
claims from the store and can add per-client claims:

```csharp
if (context.Client.ClientId == "sample-webapp")
    context.Claims["sample_webapp_specific_claim"] = "dynamically_added_value";
```

`IsUserActiveAsync` is also where you block suspended users from getting new tokens.

## Brute-force protection (host-owned)

The library calls `ICustomAuthLoginAttemptTracker` but ships a no-op default. This sample registers a
demo tracker and a rate limiter:

```csharp
builder.Services.AddSingleton<ICustomAuthLoginAttemptTracker, DemoLoginAttemptTracker>(); // 5 fails => 5 min lockout
builder.Services.AddRateLimiter(...);   // POST /login: 10 requests / minute / IP
app.UseRateLimiter();
```

Both are in-memory/per-instance for the demo. Back them with a durable/distributed store in production.

## Login / logout pages (host-owned)

The library is UI-free: it only handles `POST /login` and `GET|POST /connect/logout`. This sample owns
the Razor pages under `Pages/Login` and `Pages/Logout`, which post back to those endpoints. After a
failed login the library redirects to `LoginPath?error=<code>`; the page maps the code to a message.

## Logging / diagnostics

`appsettings.Development.json` raises the endpoint category so protocol-level diagnostics are visible:

```jsonc
"Vefa.CustomAuth.AspNetCore.Endpoints": "Debug"
```

These logs explain *why* an authorize/token/client-auth request was rejected (redirect_uri mismatch,
PKCE failure, invalid client assertion, etc.) without leaking the reason to the caller.

## Data Protection (session cookie)

The SSO session cookie and antiforgery tokens are encrypted/signed with ASP.NET Core Data Protection.
The library uses the host's `IDataProtectionProvider`; this sample wires the key ring to **SQLite** via
`Microsoft.AspNetCore.DataProtection.EntityFrameworkCore` so the keys persist and are shareable:

```csharp
builder.Services.AddDbContext<SampleDataProtectionDbContext>(o =>
    o.UseSqlite("Data Source=dataprotection-sample.db"));

builder.Services.AddDataProtection()
    .SetApplicationName("vefa-customauth-authserver")     // identical on every instance
    .PersistKeysToDbContext<SampleDataProtectionDbContext>();
```

`SampleDataProtectionDbContext` implements `IDataProtectionKeyContext` and lives in its own SQLite
database (`dataprotection-sample.db`). Because the keys are persisted and the application name is
fixed, cookies survive restarts and any instance behind a load balancer can read another's cookies —
this is the web-farm fix. For production, also encrypt the keys at rest (`ProtectKeysWith...`) and use
shared storage (a shared DB, Redis, or Azure Blob). See the
[production hardening guide](../../docs/production-hardening.md#load-balanced--web-farm-deployments).

## CORS

`AddCors` with an allow-all default policy is enabled for local convenience. Restrict origins in
production.
