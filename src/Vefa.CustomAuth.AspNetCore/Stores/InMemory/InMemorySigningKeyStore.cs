using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthSigningKeyStore"/>.
/// On first use the signing credentials provider bootstraps a fresh RSA key
/// into this store; restarts therefore rotate all tokens.
/// </summary>
public sealed class InMemorySigningKeyStore : ICustomAuthSigningKeyStore
{
    private readonly ConcurrentDictionary<string, CustomAuthSigningKey> _keys = new(StringComparer.Ordinal);

    public Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        CustomAuthSigningKey? active = null;
        foreach (var key in _keys.Values)
        {
            if (!key.IsActive)
            {
                continue;
            }

            if (active is null || key.CreatedAt > active.CreatedAt)
            {
                active = key;
            }
        }

        return Task.FromResult(active);
    }

    public Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<CustomAuthSigningKey> snapshot = _keys.Values.ToList();
        return Task.FromResult(snapshot);
    }

    public Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        _keys[key.KeyId] = key;
        return Task.CompletedTask;
    }
}
