# Vefa.CustomAuth.MongoDB

MongoDB persistence provider for Vefa.CustomAuth.

This package provides MongoDB-backed implementations of the Vefa.CustomAuth store interfaces, collection mapping, index helpers, and cleanup services.

## Typical Usage

```csharp
builder.Services.AddCustomAuthMongoDbStores(options =>
{
    options.ConnectionString = "mongodb://localhost:27017";
    options.DatabaseName = "customauth";
});
```

## Notes

Configure collection names through `CustomAuthMongoDbOptions` when the defaults do not fit the host application. Ensure indexes are created before production use.
