# Vefa.CustomAuth.AdminUI

Embedded Admin UI for Vefa.CustomAuth.

This package maps a small browser-based administration surface for clients, scopes, sessions, refresh tokens, signing keys, and audit logs. It uses the provider-neutral manager contracts from `Vefa.CustomAuth.Core`.

## Typical Usage

```csharp
app.MapVefaCustomAuthAdminUI("/customauth")
    .RequireAuthorization();
```

The Admin UI can also be configured with options:

```csharp
app.MapVefaCustomAuthAdminUI(options =>
{
    options.PathPrefix = "/customauth";
    options.DefaultPageSize = 20;
    options.MaxPageSize = 100;
});
```

## Security Notes

Do not expose the Admin UI anonymously in production. Always protect it with host application authorization.
