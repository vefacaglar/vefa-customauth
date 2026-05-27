# Vefa.CustomAuth — Phase 2 Plan

## Provider-Agnostic Persistence and Embedded Admin UI

Phase 2 focuses on making `Vefa.CustomAuth` usable beyond a single EF Core-based implementation. The main goal is to support multiple persistence providers while keeping the OAuth/OIDC runtime and the embedded Admin UI independent from any concrete database technology.

The Admin UI must work the same way whether the project uses EF Core, PostgreSQL, SQL Server, MySQL, SQLite, MongoDB, or a fully custom persistence implementation.

---

## 1. Phase 2 Goal

The goal of Phase 2 is to introduce a provider-agnostic persistence architecture.

`Vefa.CustomAuth` should not assume that authentication data is stored in a relational database, EF Core DbContext, MongoDB collection, or any specific storage engine.

Instead, all runtime and management operations must go through stable abstractions.

```text
Admin UI
  ↓
Managers
  ↓
Store interfaces
  ↓
Persistence provider implementation
```

The following dependency direction must be avoided:

```text
Admin UI
  ↓
EF Core DbContext
```

The Admin UI must not directly reference EF Core, MongoDB, PostgreSQL, SQL Server, MySQL, SQLite, or any provider-specific package.

---

## 2. Main Design Principle

The core rule:

```text
Runtime endpoints and Admin UI depend on managers.
Managers depend on store abstractions.
Store implementations depend on concrete persistence providers.
```

This keeps the project modular and allows database providers to be added without changing the OAuth/OIDC endpoint layer or the Admin UI layer.

---

## 3. Package Structure

Recommended package structure for Phase 2:

```text
Vefa.CustomAuth.Core
Vefa.CustomAuth.AspNetCore
Vefa.CustomAuth.EntityFrameworkCore
Vefa.CustomAuth.MongoDB
Vefa.CustomAuth.AdminUI
Vefa.CustomAuth.Testing
```

Optional provider-specific EF Core packages can be added later if needed:

```text
Vefa.CustomAuth.EntityFrameworkCore.PostgreSql
Vefa.CustomAuth.EntityFrameworkCore.SqlServer
Vefa.CustomAuth.EntityFrameworkCore.MySql
Vefa.CustomAuth.EntityFrameworkCore.Sqlite
```

These provider-specific packages should only be introduced if there is a real need for provider-specific migrations, indexing, optimized queries, or database-specific behavior.

For the first Phase 2 implementation, one EF Core package should be enough for PostgreSQL, SQL Server, MySQL, and SQLite.

MongoDB should be a separate package because its storage model, indexing approach, query behavior, and transaction model are different from relational databases.

---

## 4. Target Persistence Providers

### 4.1 EF Core Provider

Package:

```text
Vefa.CustomAuth.EntityFrameworkCore
```

Target databases through EF Core providers:

```text
PostgreSQL
SQL Server
MySQL / MariaDB
SQLite
```

This package should provide:

```text
CustomAuthDbContext
Entity configurations
EF Core store implementations
Migration support
Index definitions
Concurrency handling
```

The EF Core provider should be the default relational provider.

---

### 4.2 MongoDB Provider

Package:

```text
Vefa.CustomAuth.MongoDB
```

This package should provide:

```text
MongoDB store implementations
Collection mappings
Index definitions
TTL indexes where useful
Optimistic concurrency strategy if needed
```

MongoDB should not try to mimic EF Core internally. It should implement the same store contracts using MongoDB-native patterns.

---

### 4.3 Custom Provider Support

Developers should be able to implement their own persistence provider by implementing the store interfaces from `Vefa.CustomAuth.Core`.

Example use cases:

```text
Dapper-based relational implementation
Redis-backed temporary token storage
Custom internal database layer
Cloud-native document database
Existing identity database integration
```

The core package should not block these scenarios.

---

## 5. Store Abstractions

The following store interfaces should live in `Vefa.CustomAuth.Core`:

```csharp
public interface ICustomAuthClientStore
{
}

public interface ICustomAuthScopeStore
{
}

public interface ICustomAuthAuthorizationCodeStore
{
}

public interface ICustomAuthRefreshTokenStore
{
}

public interface ICustomAuthSessionStore
{
}

public interface ICustomAuthSigningKeyStore
{
}

public interface ICustomAuthAuditLogStore
{
}
```

These interfaces should not expose EF Core-specific concepts such as:

```text
DbContext
IQueryable
DbSet
EntityEntry
Expression<Func<T, bool>>
```

They also should not expose MongoDB-specific concepts such as:

```text
IMongoCollection
FilterDefinition
ObjectId
BsonDocument
```

Store contracts should use CustomAuth domain models, value objects, request models, and result models only.

---

## 6. Manager Layer

The manager layer should sit above stores and contain business rules.

Recommended manager interfaces:

```csharp
public interface ICustomAuthClientManager
{
}

public interface ICustomAuthScopeManager
{
}

public interface ICustomAuthTokenManager
{
}

public interface ICustomAuthSessionManager
{
}

public interface ICustomAuthSigningKeyManager
{
}

public interface ICustomAuthAuditLogManager
{
}
```

Managers are responsible for:

```text
Validation
Business rules
Normalization
Conflict checks
Security-sensitive decisions
Calling one or more stores when needed
Provider-independent behavior
```

Stores are responsible for:

```text
Persistence
Lookups
Insert/update/delete operations
Provider-specific data access
Concurrency checks
```

Admin UI and OAuth/OIDC endpoints should use managers, not stores directly, unless there is a strong reason to do otherwise.

---

## 7. Admin UI Compatibility Requirement

Package:

```text
Vefa.CustomAuth.AdminUI
```

The Admin UI must be provider-agnostic.

It should only depend on:

```text
Vefa.CustomAuth.Core
Vefa.CustomAuth.AspNetCore
Manager interfaces
Options/configuration models
```

It must not depend on:

```text
Vefa.CustomAuth.EntityFrameworkCore
Vefa.CustomAuth.MongoDB
Microsoft.EntityFrameworkCore
MongoDB.Driver
Npgsql
SqlServer provider packages
MySQL provider packages
```

This means the same Admin UI should work with:

```text
EF Core + PostgreSQL
EF Core + SQL Server
EF Core + MySQL
EF Core + SQLite
MongoDB
Custom store implementation
```

---

## 8. Admin UI Features for Phase 2

The first version of the embedded Admin UI should focus on client management.

Minimum features:

```text
Client list
Create client
Edit client
Disable / enable client
Delete client if safe
Manage redirect URIs
Manage post-logout redirect URIs
Manage allowed scopes
Configure token lifetimes
Configure PKCE requirement
Configure refresh token permission
View generated OIDC client settings
Copy authorize/token/userinfo/discovery URLs
```

Useful follow-up features:

```text
Scope management
Active session viewer
Refresh token viewer
Refresh token revocation
Signing key viewer
Signing key rotation trigger
Audit log viewer
Test authorization flow
```

The Admin UI should be optional and must not be enabled automatically.

Example usage:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddAdminUI();

app.MapVefaCustomAuthEndpoints();

app.MapVefaCustomAuthAdminUI("/customauth")
   .RequireAuthorization("CustomAuthAdmin");
```

---

## 9. Admin API Endpoints

The embedded Admin UI can expose internal admin APIs under a dedicated route prefix.

Example:

```text
/customauth
/customauth/api/clients
/customauth/api/scopes
/customauth/api/sessions
/customauth/api/tokens
/customauth/api/signing-keys
/customauth/api/audit-logs
```

These APIs should call manager services, not database providers directly.

Example flow:

```text
POST /customauth/api/clients
  ↓
CustomAuthClientManager.CreateAsync(...)
  ↓
ICustomAuthClientStore.CreateAsync(...)
  ↓
EF Core / MongoDB / custom provider implementation
```

---

## 10. Security Requirements for Admin UI

The Admin UI is sensitive and must be secure by default.

Requirements:

```text
Admin UI must be opt-in.
Admin UI must support RequireAuthorization.
Admin UI must not expose secrets by default.
Client secrets, if supported later, must only be shown once after creation.
Dangerous actions must require explicit confirmation.
Audit logs should be written for create/update/delete/revoke actions.
CSRF protection should be considered for browser-based admin actions.
Admin API routes should not be accessible anonymously.
Admin UI should be easy to disable in production.
```

The recommended default is:

```text
Do not map Admin UI unless the host application explicitly calls MapVefaCustomAuthAdminUI.
```

---

## 11. Provider Registration Design

The library should support provider registration through extension methods.

EF Core example:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddEntityFrameworkStores<AppDbContext>();
```

MongoDB example:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddMongoDbStores(options =>
    {
        options.ConnectionString = connectionString;
        options.DatabaseName = "customauth";
    });
```

Custom provider example:

```csharp
builder.Services
    .AddVefaCustomAuth(options =>
    {
        options.Issuer = "https://auth.local";
    })
    .AddStores<CustomClientStore,
               CustomScopeStore,
               CustomAuthorizationCodeStore,
               CustomRefreshTokenStore,
               CustomSessionStore,
               CustomSigningKeyStore,
               CustomAuditLogStore>();
```

Exact API shape can change, but the goal should remain:

```text
Runtime setup is independent from persistence provider choice.
```

---

## 12. Data Model Compatibility

Core domain models should be persistence-neutral.

Avoid provider-specific IDs in public contracts.

Prefer:

```text
string Id
string ClientId
string UserId
DateTimeOffset CreatedAt
DateTimeOffset ExpiresAt
```

Avoid leaking:

```text
Guid-only assumptions
long identity-only assumptions
MongoDB ObjectId assumptions
EF Core navigation property assumptions
```

Provider implementations can map these models to their own internal storage format.

---

## 13. Query and Pagination Contracts

Admin UI will need list/search screens.

Core should define provider-neutral query models:

```csharp
public sealed class CustomAuthPagedRequest
{
    public int Page { get; init; }
    public int PageSize { get; init; }
    public string? Search { get; init; }
}

public sealed class CustomAuthPagedResult<T>
{
    public IReadOnlyList<T> Items { get; init; }
    public int TotalCount { get; init; }
}
```

Store interfaces should return provider-neutral paged results.

Admin UI should not build database queries itself.

---

## 14. Audit Logging

Phase 2 should introduce audit logging contracts because Admin UI actions need traceability.

Audit examples:

```text
ClientCreated
ClientUpdated
ClientDisabled
ClientDeleted
RedirectUriAdded
RedirectUriRemoved
ScopeAdded
ScopeRemoved
RefreshTokenRevoked
SessionRevoked
SigningKeyRotated
```

Audit log records should include:

```text
Action
ActorUserId
TargetType
TargetId
Timestamp
IpAddress
UserAgent
Metadata
```

The audit log store should also be provider-agnostic.

---

## 15. Indexing Requirements

Each provider package should define its own indexes.

Required relational indexes:

```text
Clients: ClientId unique
AuthorizationCodes: CodeHash unique
AuthorizationCodes: ClientId
AuthorizationCodes: UserId
AuthorizationCodes: ExpiresAt
RefreshTokens: TokenHash unique
RefreshTokens: ClientId
RefreshTokens: UserId
RefreshTokens: SessionId
RefreshTokens: ExpiresAt
Sessions: UserId
Sessions: ExpiresAt
SigningKeys: KeyId unique
AuditLogs: Timestamp
AuditLogs: ActorUserId
AuditLogs: TargetType + TargetId
```

MongoDB should define equivalent indexes.

TTL indexes can be considered for expired authorization codes and sessions, but cleanup should not rely only on TTL behavior.

---

## 16. Cleanup Jobs

Phase 2 should define provider-neutral cleanup services.

Cleanup targets:

```text
Expired authorization codes
Consumed authorization codes older than configured retention
Expired refresh tokens
Revoked refresh tokens older than configured retention
Expired sessions
Old audit logs if retention is configured
```

The cleanup service should call store abstractions.

Example:

```csharp
public interface ICustomAuthCleanupService
{
    Task CleanupAsync(CancellationToken cancellationToken = default);
}
```

Each provider can optimize cleanup internally.

---

## 17. Testing Requirements

Provider-agnostic behavior must be covered by shared contract tests.

Test strategy:

```text
Core manager tests
Admin API tests with in-memory/fake stores
EF Core provider tests
MongoDB provider tests
Store contract tests reused by all providers
```

Store contract tests should verify:

```text
Create client
Update client
Find client by ClientId
List clients with pagination
Store authorization code
Consume authorization code once
Reject expired authorization code
Store refresh token
Rotate refresh token
Revoke refresh token
Create session
Revoke session
Read signing keys
Write audit logs
```

The same test suite should be reusable across EF Core, MongoDB, and custom provider test implementations.

---

## 18. Phase 2 Roadmap

### v0.5 — Manager Layer and Store Contracts

```text
Finalize provider-neutral store interfaces
Introduce manager layer
Move business rules out of endpoint handlers
Add provider-neutral query/pagination contracts
Add audit log contracts
```

### v0.6 — EF Core Provider

```text
Implement EF Core stores
Support PostgreSQL through EF Core
Support SQL Server through EF Core
Support MySQL through EF Core
Support SQLite through EF Core
Add relational indexes
Add migrations
Add cleanup service implementation
```

### v0.7 — Embedded Admin UI v1

```text
Add optional Admin UI package
Add client management screens
Add admin API endpoints
Add authorization integration
Add audit logging for admin actions
Add generated client configuration view
```

### v0.8 — MongoDB Provider

```text
Implement MongoDB stores
Add MongoDB collection mappings
Add MongoDB indexes
Add MongoDB cleanup implementation
Run shared store contract tests against MongoDB
```

### v0.9 — Admin UI Extended Management

```text
Scope management
Session viewer
Refresh token viewer
Token/session revocation
Signing key viewer
Audit log viewer
Test authorization flow screen
```

### v1.0 — Stable Provider API

```text
Stabilize public store interfaces
Stabilize manager contracts
Stabilize Admin UI extension points
Document custom provider implementation
Document EF Core setup
Document MongoDB setup
Add production hardening checklist
```

---

## 19. Non-Goals for Phase 2

Phase 2 should not try to solve everything.

Not required yet:

```text
Full multi-tenant admin UI
Complex role/permission system inside CustomAuth itself
Enterprise-level policy engine
Distributed cache provider abstraction
Hosted SaaS management portal
External identity provider federation
SAML support
Dynamic UI plugin system
```

These can be considered later, but Phase 2 should focus on persistence abstraction and provider-compatible Admin UI.

---

## 20. Final Architecture Target

The intended architecture after Phase 2:

```text
Vefa.CustomAuth.Core
  Domain models
  Options
  Store interfaces
  Manager interfaces
  Provider-neutral contracts

Vefa.CustomAuth.AspNetCore
  OAuth/OIDC endpoints
  Login/logout endpoints
  Discovery/JWKS endpoints
  Runtime service registration

Vefa.CustomAuth.EntityFrameworkCore
  EF Core DbContext
  Entity mappings
  EF Core stores
  Relational database support

Vefa.CustomAuth.MongoDB
  MongoDB stores
  Collection mappings
  MongoDB indexes

Vefa.CustomAuth.AdminUI
  Embedded management UI
  Admin API endpoints
  Client/scope/session/token/signing-key management
  Provider-agnostic manager-based operations
```

The important rule is simple:

```text
Admin UI and runtime endpoints must not care where the data is stored.
```

This is the core design requirement for Phase 2.
