# Vefa.CustomAuth.AdminUI

Embedded Admin UI for Vefa.CustomAuth.

This package maps a small browser-based administration surface for clients, scopes, sessions, refresh tokens, signing keys, and audit logs. It uses the provider-neutral manager contracts from `Vefa.CustomAuth.Core`.

The client editor manages redirect URIs, post-logout redirect URIs, and allowed scopes as separate
items. The Admin UI submits the same public `CustomAuthClient` JSON shape (`redirectUris`,
`postLogoutRedirectUris`, `allowedScopes`) while EF Core providers persist those values as relational
child rows.

## Typical Usage

```csharp
app.MapCustomAuthAdminUI("/customauth")
    .RequireAuthorization();
```

The Admin UI can also be configured with options:

```csharp
app.MapCustomAuthAdminUI(options =>
{
    options.PathPrefix = "/customauth";
    options.DefaultPageSize = 20;
    options.MaxPageSize = 100;
});
```

## Security Notes

Do not expose the Admin UI anonymously in production. Always protect it with host application authorization.
