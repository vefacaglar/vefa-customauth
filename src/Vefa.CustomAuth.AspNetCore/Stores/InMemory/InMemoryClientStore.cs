using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthClientStore"/>.
/// Intended for samples, integration tests, and the v0.1 milestone.
/// Not safe for production multi-instance deployments.
/// </summary>
public sealed class InMemoryClientStore : ICustomAuthClientStore
{
    private readonly ConcurrentDictionary<string, CustomAuthClient> _clients;

    public InMemoryClientStore(IEnumerable<CustomAuthClient>? seed = null)
    {
        _clients = new ConcurrentDictionary<string, CustomAuthClient>(StringComparer.Ordinal);
        if (seed is null)
        {
            return;
        }

        foreach (var client in seed)
        {
            _clients[client.ClientId] = client;
        }
    }

    public Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }
}
