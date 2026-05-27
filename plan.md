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

A developer should be able to add the library to an ASP.NET Core project like this:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddJwtTokenSigning();

app.MapVefaCustomAuthEndpoints();
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

### v0.1

```text
GET  /connect/authorize
POST /connect/token
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /login
POST /login
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

Refresh tokens must be:

```text
stored as hashes
rotated after use
bound to client_id
bound to user_id
optionally bound to session_id
```

Reuse detection should be added after the basic rotation flow is working.

Suggested model:

```csharp
public sealed class CustomAuthRefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; }
    public string ClientId { get; set; }
    public string UserId { get; set; }
    public string? SessionId { get; set; }
    public string Scope { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
```

For the first version, refresh token rotation is enough. Reuse detection can be added in v0.2 or later.

---

## 10. Session / SSO Cookie

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

`Vefa.CustomAuth.AspNetCore` should provide the ASP.NET Core integration layer.

Main extension methods:

```csharp
AddVefaCustomAuth(...)
MapVefaCustomAuthEndpoints()
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
builder.Services.AddVefaCustomAuthEntityFrameworkCore(options =>
{
    options.UseNpgsql(connectionString);
});
```

A more flexible option:

```csharp
builder.Services.AddVefaCustomAuthStores<AppDbContext>();
```

The second approach is probably better in the long term because it lets the consumer keep the auth tables inside their own application DbContext.

---

## 14. Security Requirements

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

```text
Security hardening
Stable public API
Migration strategy
Package versioning policy
```

---

## Recommended First Milestone

The first milestone should be:

```text
v0.1: a working Authorization Code + PKCE flow using in-memory stores
```

EF Core should not be implemented too early. The protocol flow should work first. After the flow is stable, persistence can be introduced behind store interfaces.

This prevents the project from getting stuck in database design before the core authentication flow is proven.
