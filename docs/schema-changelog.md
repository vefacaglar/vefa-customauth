---
title: Schema changelog
description: Relational (EF Core) schema changes per version and the host migration steps each one requires.
---

# Schema changelog

This page records every change to the **relational (EF Core) schema** shipped by
`Vefa.CustomAuth.EntityFrameworkCore`, and the action each one requires from host applications.

The library does **not** ship EF Core migrations — hosts own their `DbContext` and generate their
own migrations (or call `EnsureCreated`). Use this page to know what changed when you upgrade.

- **EF Core hosts** must add a migration (`dotnet ef migrations add ...`) or recreate the schema.
- **MongoDB hosts** need no action — the provider is schemaless and new fields are mapped
  automatically via `AutoMap`.
- **In-memory hosts** need no action.

## v1.3 — Audience model (scope audiences + RFC 8707 resources)

Added the resource/audience model: scopes can map to an API audience, and grants record the
RFC 8707 resource indicators they were issued for.

| Table | New column | Type |
| --- | --- | --- |
| `CustomAuthScopes` | `Audience` | `nvarchar(512)` / `TEXT`, nullable |
| `CustomAuthAuthorizationCodes` | `Resources` | `nvarchar(2000)` / `TEXT`, nullable (space-delimited) |
| `CustomAuthRefreshTokens` | `Resources` | `nvarchar(2000)` / `TEXT`, nullable (space-delimited) |

Rows with `NULL` values keep the previous behavior: access tokens fall back to `aud = client_id`
when no granted scope maps to an audience.

**Host action (EF Core):**

```bash
dotnet ef migrations add AddCustomAuthAudienceModel
dotnet ef database update
```

No action required for MongoDB or in-memory hosts.

## v1.2 — `AuthTime` on authorization codes

Added a nullable `AuthTime` column to `CustomAuthAuthorizationCodes`. It records when the end user
originally authenticated for the SSO session that issued the code, and is emitted as the
`auth_time` claim of the ID token (previously the claim used the code's `CreatedAt`, which
overstated authentication freshness under SSO).

| Table | New column | Type |
| --- | --- | --- |
| `CustomAuthAuthorizationCodes` | `AuthTime` | `datetimeoffset` / `TEXT`, nullable |

Codes stored before the upgrade have a `NULL` `AuthTime`; token issuance falls back to `CreatedAt`
for them.

**Host action (EF Core):**

```bash
dotnet ef migrations add AddAuthorizationCodeAuthTime
dotnet ef database update
```

No action required for MongoDB or in-memory hosts.

## v1.1 — `Properties` extensibility bag

Added a free-form `IDictionary<string, string> Properties` bag to three models as a
forward-compatibility extension point (resource/audience values, custom claim mappings, feature
flags, `acr`/`amr`, device binding, and similar additive features can use it without further schema
changes):

| Table | New column | Type |
| --- | --- | --- |
| `CustomAuthClients` | `Properties` | JSON text (`nvarchar(max)` / `TEXT`), not null |
| `CustomAuthScopes` | `Properties` | JSON text (`nvarchar(max)` / `TEXT`), not null |
| `CustomAuthSessions` | `Properties` | JSON text (`nvarchar(max)` / `TEXT`), not null |

The column stores the dictionary serialized as JSON; an absent/empty value reads back as an empty
dictionary (never null).

**Host action (EF Core):**

```bash
dotnet ef migrations add AddCustomAuthPropertiesBag
dotnet ef database update
```

No action required for MongoDB or in-memory hosts.
