# Vefa.CustomAuth.EntityFrameworkCore

EF Core persistence provider for Vefa.CustomAuth.

This package provides `CustomAuthDbContext`, EF Core entity configuration, store implementations, and cleanup services for relational databases supported by EF Core.

## Typical Usage

```csharp
builder.Services.AddCustomAuthEntityFrameworkCore(options =>
{
    options.UseSqlite(connectionString);
});
```

If the host application owns the `DbContext`, apply the CustomAuth model configuration and register stores for that context:

```csharp
builder.Services.AddCustomAuthStores<AppDbContext>();
```

## Client Relations

`CustomAuthClient.RedirectUris`, `CustomAuthClient.PostLogoutRedirectUris`, and
`CustomAuthClient.AllowedScopes` are exposed as `List<string>` in the public model. EF Core persists
them as relational one-to-many child rows:

| Default table | Contents |
| --- | --- |
| `CustomAuthClientRedirectUris` | Allowed authorization redirect URIs. |
| `CustomAuthClientPostLogoutRedirectUris` | Allowed post-logout redirect URIs. |
| `CustomAuthClientAllowedScopes` | Scopes the client may request. |

If you derive from `CustomAuthDbContext`, you may override table names in `OnModelCreating` after
calling `base.OnModelCreating(modelBuilder)`.

## Notes

The EF Core provider stores authorization codes and refresh tokens as hashes. Configure migrations and indexes for the selected database provider before production use.
