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

## Notes

The EF Core provider stores authorization codes and refresh tokens as hashes. Configure migrations and indexes for the selected database provider before production use.
