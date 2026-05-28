# Vefa.CustomAuth.Core

Core abstractions and domain models for Vefa.CustomAuth.

This package contains provider-neutral models, store interfaces, manager interfaces, options, and cleanup abstractions. It does not depend on ASP.NET Core, EF Core, MongoDB, or token signing libraries.

## Typical Usage

Reference this package when implementing a custom persistence provider or integrating Vefa.CustomAuth with a host-owned user store.

```csharp
public sealed class AppUserStore : ICustomAuthUserStore
{
    public Task<CustomAuthUserInfo?> ValidateCredentialsAsync(
        string userName,
        string password,
        CancellationToken cancellationToken = default)
    {
        // Validate credentials against the host application user database.
        throw new NotImplementedException();
    }

    public Task<CustomAuthUserInfo?> FindByIdAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        // Resolve profile information for tokens and userinfo responses.
        throw new NotImplementedException();
    }
}
```

## Notes

Store implementations should persist only hashed authorization codes and hashed refresh tokens. Host applications own user persistence and should implement `ICustomAuthUserStore`.
