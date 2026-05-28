# Vefa.CustomAuth Requirements Plan

## Purpose

`Vefa.CustomAuth` is intended to be a lightweight OAuth2 / OpenID Connect based custom SSO library for ASP.NET Core applications.

The goal is not to build a full IdentityServer replacement in the first version. The initial goal is to support a clean, maintainable, and package-friendly implementation of the most common SSO flow:

```text
Authorization Code Flow + PKCE
SSO session cookie
JWT access token
ID token
Refresh token
JWKS endpoint
ASP.NET Core endpoint mapping
EF Core persistence
```

The project should first be built as a complete working reference implementation. After the core flow is stable, the reusable parts can be split into NuGet packages.

---

## 1. Solution Structure

Status: completed

```text
Vefa.CustomAuth.sln

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

`Vefa.CustomAuth.Tokens` may not be required as a separate package in the first version. Token-related code can initially live inside `Core` or `AspNetCore` and be extracted later if it grows.

Minimum NuGet package targets:

```text
Vefa.CustomAuth.Core
Vefa.CustomAuth.AspNetCore
Vefa.CustomAuth.EntityFrameworkCore
```

---

## 2. Intended Usage

Status: completed

A developer should be able to add the library to an ASP.NET Core project like this:

```csharp
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddJwtTokenSigning();

builder.Services.AddCustomAuthStores<AppDbContext>();

app.MapCustomAuthEndpoints();
```

A protected API should be able to validate access tokens using the standard JWT bearer authentication flow:

```csharp
builder.Services
    .AddAuthentication("Bearer")
    .AddJwtBearer(...);
```

Client applications should be able to connect to the auth server using a normal OIDC client configuration.

---

## 3. Supported Endpoints

Status: partial — v0.1 and v0.2 routes (discovery, JWKS, authorize, token, login, logout, userinfo, revoke) are fully completed; introspection and consent are deferred beyond the current SSO-focused scope unless explicitly prioritized.

### v0.1

```text
GET  /connect/authorize
POST /connect/token
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
POST /login   (credential validation only — host owns the GET / sign-in UI)
```

### v0.2

```text
POST /connect/logout
GET  /connect/userinfo
POST /connect/revoke
```

### v0.3+

```text
POST /connect/introspect
GET  /consent
POST /consent
```

A consent screen is not required in the first version. For SSO between your own applications, it adds unnecessary complexity at the beginning.

---

## 4. Supported OAuth2 / OIDC Flows

Status: completed

The first version should support only:

```text
Authorization Code Flow + PKCE
```

The following flows should not be supported initially:

```text
Implicit Flow
Password Grant
Device Code
Client Credentials
Hybrid Flow
```

`Client Credentials` can be added later, but it is not required for the first SSO use case.

---

## 5. Domain Models

Status: completed

Minimum required models:

```csharp
CustomAuthClient
CustomAuthAuthorizationCode
CustomAuthRefreshToken
CustomAuthSession
CustomAuthSigningKey
```

The user model should not be hardcoded into the package.

Instead, the package should expose a user abstraction:

```csharp
ICustomAuthUserStore
```

A sample user model can exist in the sample project, but the main package should not force consumers to use a specific user table or identity model.

---

## 6. Client Model

Status: completed

```csharp
public sealed class CustomAuthClient
{
    public string ClientId { get; set; }
    public string DisplayName { get; set; }

    public List<string> RedirectUris { get; set; }
    public List<string> PostLogoutRedirectUris { get; set; }

    public List<string> AllowedScopes { get; set; }

    public bool RequirePkce { get; set; } = true;
    public bool AllowRefreshTokens { get; set; } = true;

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;
}
```

The client configuration should enforce exact redirect URI matching. Partial or wildcard redirect URI matching should be avoided in the first version.

---

## 7. Authorization Code Requirements

Status: completed

Authorization codes must be:

```text
single-use
short-lived
bound to the PKCE code_challenge
bound to the client_id
bound to the redirect_uri
bound to the user_id
```

Recommended lifetime:

```text
60-120 seconds
```

Suggested model:

```csharp
public sealed class CustomAuthAuthorizationCode
{
    public Guid Id { get; set; }
    public string CodeHash { get; set; }
    public string ClientId { get; set; }
    public string UserId { get; set; }
    public string RedirectUri { get; set; }
    public string CodeChallenge { get; set; }
    public string CodeChallengeMethod { get; set; }
    public string Scope { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
```

The raw authorization code should not be stored in the database. Only a hash of the code should be stored.

---

## 8. Token Requirements

Status: completed

The system should issue the following tokens:

```text
access_token
id_token
refresh_token
```

The access token can be a JWT.

The ID token should be a JWT because it belongs to the OpenID Connect layer.

The refresh token should be an opaque random value. It does not need to be a JWT.

### Access Token Claims

```text
sub
iss
aud
exp
iat
jti
scope
```

### ID Token Claims

```text
sub
iss
aud
exp
iat
auth_time
name
email
```

`name` and `email` should not be required. The user store should provide whatever profile data is available.

---

## 9. Refresh Token Requirements

Status: completed

Refresh tokens must be:

```text
stored as hashes
rotated after use
bound to client_id
bound to user_id
optionally bound to session_id
```

Reuse detection is part of the refresh token lifecycle.

Suggested model:

```csharp
public sealed class CustomAuthRefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; }
    public string ClientId { get; set; }
    public string UserId { get; set; }
    public Guid? SessionId { get; set; }
    public Guid? ParentTokenId { get; set; }
    public string Scope { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset AbsoluteExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
```

Refresh tokens support rotation, session binding, parent-token tracking, absolute expiration, revocation, and reuse detection.

---

## 10. Session / SSO Cookie

Status: completed

The auth server should issue its own session cookie.

Suggested defaults:

```text
Cookie name: .Vefa.CustomAuth.Session
HttpOnly: true
Secure: true
SameSite: Lax
```

This cookie is the core mechanism behind SSO.

If the user logs in through App A, the auth server stores the session cookie. Later, when App B redirects the user to `/connect/authorize`, the auth server can detect the existing session and issue a new authorization code without asking the user to log in again.

---

## 11. Store Interfaces

Status: completed

The `Core` package should contain abstractions only.

```csharp
ICustomAuthClientStore
ICustomAuthAuthorizationCodeStore
ICustomAuthRefreshTokenStore
ICustomAuthSessionStore
ICustomAuthSigningKeyStore
ICustomAuthUserStore
```

The EF Core package should provide default implementations of these interfaces.

---

## 12. ASP.NET Core Package

Status: completed

`Vefa.CustomAuth.AspNetCore` should provide the ASP.NET Core integration layer.

Main extension methods:

```csharp
AddCustomAuth(...)
MapCustomAuthEndpoints()
```

Endpoint handlers should live here:

```text
AuthorizeEndpoint
TokenEndpoint
LoginEndpoint
LogoutEndpoint
DiscoveryEndpoint
JwksEndpoint
UserInfoEndpoint
```

Minimal API endpoint mapping is preferable to controllers because it is more package-friendly and easier to plug into host applications.

---

## 13. EF Core Package

Status: completed

`Vefa.CustomAuth.EntityFrameworkCore` should provide persistence support.

Expected components:

```csharp
CustomAuthDbContext
CustomAuthEntityConfigurations
EfCustomAuthClientStore
EfCustomAuthAuthorizationCodeStore
EfCustomAuthRefreshTokenStore
EfCustomAuthSessionStore
EfCustomAuthSigningKeyStore
```

Possible usage:

```csharp
builder.Services.AddCustomAuthEntityFrameworkCore(options =>
{
    options.UseNpgsql(connectionString);
});
```

A more flexible option:

```csharp
builder.Services.AddCustomAuthStores<AppDbContext>();
```

The second approach is probably better in the long term because it lets the consumer keep the auth tables inside their own application DbContext.

---

## 14. Security Requirements

Status: completed

Minimum security rules:

```text
PKCE should be required
redirect_uri must use exact matching
state should be validated by the client
authorization codes must be single-use
authorization codes must expire quickly
raw authorization codes must not be stored
refresh tokens must be stored as hashes
token signing private keys must stay private
open redirects must be prevented
issuer and audience must be validated correctly
HTTPS should be required in production
```

Client secret support is not required in the first version. Public clients with PKCE are enough for the initial SSO scenario.

---

## 15. Configuration Requirements

Status: completed

Suggested options model:

```csharp
public sealed class CustomAuthOptions
{
    public string Issuer { get; set; }

    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    public string LoginPath { get; set; } = "/login";
    public string CookieName { get; set; } = ".Vefa.CustomAuth.Session";

    public bool RequirePkce { get; set; } = true;
    public bool RequireHttps { get; set; } = true;
}
```

Options validation should be added before publishing the package.

---

## 16. Sample Scenarios

Status: completed

At least three sample projects should exist:

```text
Auth Server
Web App Client
Protected API
```

Expected flow:

```text
The Web App requires login
The Web App redirects to the Auth Server
The Auth Server authenticates the user
The Auth Server redirects back with an authorization code
The Web App exchanges the code for tokens
The Web App calls the Protected API with the access token
The API validates the access token
```

The sample projects are important because they verify the package design before publishing NuGet packages.

---

## 17. Test Requirements

Status: completed

Priority test cases:

```text
invalid redirect_uri should be rejected
wrong PKCE verifier should be rejected
authorization code should not be usable twice
expired authorization code should be rejected
refresh token rotation should work
revoked refresh token should be rejected
JWKS endpoint should return the public signing key
JWT signature should be verifiable
issuer and audience validation should work
```

Security-related behavior should be covered with integration tests, not only unit tests.

---

## 18. Roadmap

### v0.1

```text
Authorization Code + PKCE
Login cookie
JWT access token
ID token
JWKS endpoint
Discovery endpoint
In-memory stores
```

### v0.2

```text
EF Core stores
Refresh token
Logout endpoint
UserInfo endpoint
```

### v0.3

```text
Sample Auth Server
Sample Web Client
Sample Protected API
Options validation
Basic tests
```

### v0.4

```text
NuGet package split
README
XML docs
CI package build
```

### v1.0

Status: completed — All P0, P1, and P2 security audit items are fully completed and verified with 100/100 passing tests!

```text
Security hardening
Stable public API
Migration strategy
Package versioning policy
```

---

## 19. Security Audit Remediation (RFC 6749 / 7009 / 7636 / 8414 / 9700 / OIDC Core)

Full audit findings + 21-item severity-ordered remediation roadmap (P0/P1/P2) live at `/Users/vefa/.claude/plans/first-you-need-handover-federated-nygaard.md`. Read that file before changing protocol code.

### P0 — must fix before any production deployment

Status: completed (2026-05-28)

```text
P0-1  Admin UI authorization bypass closed (MapGroup + RequireAuthorization by default)
P0-2  OIDC nonce parsed, persisted on the auth code, echoed into the ID token
P0-3  Authorize errors after redirect_uri validation now redirect with error= and state=
P0-4  Authorization code & refresh token consumption is atomic (CAS, returns bool)
P0-5  CSRF protection on /login POST via IAntiforgery
P0-6  Token endpoint sets Cache-Control: no-store and Pragma: no-cache
```

Test count after P0 work: **77** (26 store/manager + 51 AspNetCore). Build remains 0 warnings / 0 errors.

### P1 — should fix before 1.1 release

Status: completed (2026-05-28) — All P1 security audit items are fully implemented and verified with comprehensive integration tests.

```text
[x] P1-7   Add at_hash to ID token (OIDC Core §3.1.3.6)
[x] P1-8   Implement prompt=none / prompt=login (and ideally max_age)
[x] P1-9   UserInfo: support POST + filter claims by scope (OIDC Core §5.3, §5.4)
[x] P1-10  Rate limiting / lockout extension point on /login
[x] P1-11  Constant-time hash compare in PkceVerifier (CryptographicOperations.FixedTimeEquals)
[x] P1-12  Revocation hardening: client binding, token_type_hint, chain revocation
```

### P2 — hardening

Status: completed — All security audit hardening items (P2-13 through P2-20) are fully implemented and verified. P2-21 (Introspection) is deferred per roadmap requirements.

```text
[x] P2-13  Drop PKCE plain method from PkceVerifier and discovery
[x] P2-14  Lower default AuthorizationCodeLifetime to 60s
[x] P2-15  CSRF tokens on Admin UI mutating endpoints
[x] P2-16  Restrict /connect/logout state changes to POST + anti-forgery
[x] P2-17  Token endpoint returns 401 + WWW-Authenticate for invalid_client
[x] P2-18  Use __Host- cookie prefix + Data Protection wrapper for session cookie
[x] P2-19  Client redirect URI format validation (RFC 8252 §7.3)
[x] P2-20  EF Core cleanup service parity with MongoCustomAuthCleanupService
[ ] P2-21  /connect/introspect (deferred per §3 unless a real consumer needs it)
```

---

## Client Authentication: private_key_jwt (confidential clients)

Status: completed

Adds asymmetric client authentication at the token endpoint (RFC 7521 / 7523, OpenID Connect
Core §9) so confidential (service-to-service) clients can prove their identity instead of relying
on PKCE alone. Public clients keep `token_endpoint_auth_method = none` (default), so existing
behavior is unchanged.

- `CustomAuthClient` gains `TokenEndpointAuthMethod` (`None` / `PrivateKeyJwt`) and `JwksJson`
  (inline public JWKS used to verify assertions; no `jwks_uri` fetching in this iteration).
- `CustomAuthOptions.ClientAssertionClockSkew` (default 60s) bounds `exp`/`nbf` tolerance.
- `Vefa.CustomAuth.Tokens.ClientAssertion.ClientAssertionValidator` validates the assertion with
  `JsonWebTokenHandler`: signature against the client's JWKS, asymmetric algorithms only
  (`none`/HMAC rejected), `aud` ∈ {issuer, token endpoint}, `iss == sub == client_id`, `exp`/`jti`
  required.
- `jti` replay protection via `IClientAssertionReplayCache` (default in-memory
  `MemoryClientAssertionReplayCache`; swap for a distributed cache when running multiple instances).
- `ClientAuthenticationService` enforces the method in both token grants; failures return opaque
  `invalid_client` (401 + `WWW-Authenticate`) with precise server-side diagnostic logs.
- Discovery advertises `private_key_jwt` and `token_endpoint_auth_signing_alg_values_supported`.
- EF maps the new columns; Mongo picks them up via `AutoMap`. Admin UI client editor exposes the
  method selector + JWKS textarea. Sample seeds a `service-client` confidential client (public JWKS
  only). Covered by unit + integration tests (validator, end-to-end exchange, replay, forged key).

---

## Recommended First Milestone

The first milestone should be:

```text
v0.1: a working Authorization Code + PKCE flow using in-memory stores
```

EF Core should not be implemented too early. The protocol flow should work first. After the flow is stable, persistence can be introduced behind store interfaces.

This prevents the project from getting stuck in database design before the core authentication flow is proven.
