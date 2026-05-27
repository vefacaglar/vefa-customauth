using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthUserStore"/> for samples
/// and tests. Credentials are compared in constant time but the user list is
/// fully in-process; never use this for real users.
/// </summary>
public sealed class InMemoryUserStore : ICustomAuthUserStore
{
    public sealed class SeedUser
    {
        public string UserId { get; set; } = default!;
        public string UserName { get; set; } = default!;
        public string Password { get; set; } = default!;
        public string? Email { get; set; }
        public IReadOnlyDictionary<string, string>? AdditionalClaims { get; set; }
    }

    private readonly ConcurrentDictionary<string, SeedUser> _byUserName;
    private readonly ConcurrentDictionary<string, SeedUser> _byUserId;

    public InMemoryUserStore(IEnumerable<SeedUser>? seed = null)
    {
        _byUserName = new ConcurrentDictionary<string, SeedUser>(StringComparer.OrdinalIgnoreCase);
        _byUserId = new ConcurrentDictionary<string, SeedUser>(StringComparer.Ordinal);

        if (seed is null)
        {
            return;
        }

        foreach (var user in seed)
        {
            _byUserName[user.UserName] = user;
            _byUserId[user.UserId] = user;
        }
    }

    public Task<CustomAuthUserInfo?> ValidateCredentialsAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ArgumentException.ThrowIfNullOrEmpty(password);

        if (!_byUserName.TryGetValue(userName, out var user))
        {
            return Task.FromResult<CustomAuthUserInfo?>(null);
        }

        var expected = System.Text.Encoding.UTF8.GetBytes(user.Password);
        var provided = System.Text.Encoding.UTF8.GetBytes(password);
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, provided))
        {
            return Task.FromResult<CustomAuthUserInfo?>(null);
        }

        return Task.FromResult<CustomAuthUserInfo?>(ToInfo(user));
    }

    public Task<CustomAuthUserInfo?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userId);
        _byUserId.TryGetValue(userId, out var user);
        return Task.FromResult(user is null ? null : ToInfo(user));
    }

    private static CustomAuthUserInfo ToInfo(SeedUser user) => new()
    {
        UserId = user.UserId,
        UserName = user.UserName,
        Email = user.Email,
        AdditionalClaims = user.AdditionalClaims,
    };
}
