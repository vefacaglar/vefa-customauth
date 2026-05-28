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

Protocol data (clients, codes, tokens, signing keys, sessions) uses EF Core + SQLite:

```csharp
builder.Services.AddCustomAuthEntityFrameworkCore(o => o.UseSqlite("Data Source=customauth-sample.db"));
```

`DatabaseSeeder` calls `EnsureCreatedAsync` and seeds the demo clients. The `.db` files are generated
at runtime and are git-ignored. **If you change the client schema, delete `customauth-sample.db`** so it
is recreated (`EnsureCreated` does not migrate an existing database).

Swap SQLite for SQL Server / PostgreSQL by changing the `UseSqlite(...)` call.

## Seeded clients

`DatabaseSeeder` registers three clients:

| Client | Auth method | Notes |
| --- | --- | --- |
| `sample-webapp` | public (PKCE) | The Sample.WebApp relying party. |
| `swagger-ui` | public (PKCE) | Swagger UI in Sample.Api. |
| `service-client` | `private_key_jwt` | Confidential client; see below. |

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

The SSO session cookie is encrypted and signed with ASP.NET Core Data Protection. The library uses
the host's `IDataProtectionProvider`; this sample relies on the framework's default key ring, which is
fine for local development. In production, configure key persistence and at-rest encryption (and a
stable application name across instances) — see the
[production hardening guide](../../docs/production-hardening.md#data-protection).

## CORS

`AddCors` with an allow-all default policy is enabled for local convenience. Restrict origins in
production.
