using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthRefreshTokenStore"/>.
/// Tokens are looked up by their hashed form; the raw token is never stored.
/// </summary>
public sealed class InMemoryRefreshTokenStore : ICustomAuthRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, CustomAuthRefreshToken> _tokensByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Guid, CustomAuthRefreshToken> _tokensById = new();

    public Task StoreAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        _tokensByHash[token.TokenHash] = token;
        _tokensById[token.Id] = token;
        return Task.CompletedTask;
    }

    public Task<CustomAuthRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);
        _tokensByHash.TryGetValue(tokenHash, out var token);
        return Task.FromResult(token);
    }

    public Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        if (_tokensById.TryGetValue(id, out var token))
        {
            token.ConsumedAt = consumedAt;
        }

        return Task.CompletedTask;
    }

    public Task RevokeAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        if (_tokensById.TryGetValue(id, out var token))
        {
            token.RevokedAt = revokedAt;
        }

        return Task.CompletedTask;
    }
}
