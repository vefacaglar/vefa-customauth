# Vefa.CustomAuth.Server

Composition package for Vefa.CustomAuth server scenarios.

This package references the ASP.NET Core integration and EF Core persistence packages together for applications that want the default server-side stack.

## Typical Usage

Use this package when building an authorization server with the default ASP.NET Core endpoint layer and EF Core persistence provider.

```csharp
builder.Services
    .AddCustomAuth(options =>
    {
        options.Issuer = "https://auth.example.com";
    })
    .AddJwtTokenSigning();

builder.Services.AddCustomAuthEntityFrameworkCore(options =>
{
    options.UseSqlite(connectionString);
});

app.MapCustomAuthEndpoints();
```

## Notes

The EF Core provider stores client redirect URIs, post-logout redirect URIs, and allowed scopes as
relational child rows while keeping the public `CustomAuthClient` API as simple `List<string>`
properties.

For custom persistence providers, reference the lower-level packages directly instead of this composition package.
