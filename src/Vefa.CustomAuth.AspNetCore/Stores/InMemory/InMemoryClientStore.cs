using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryClientStore"/> class.
    /// </summary>
    /// <param name="seed">Optional seeded list of clients.</param>
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

    /// <inheritdoc/>
    public Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _clients.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(c =>
                c.ClientId.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                (c.DisplayName != null && c.DisplayName.Contains(search, StringComparison.OrdinalIgnoreCase))
            );
        }

        query = query.OrderBy(c => c.ClientId);

        var totalCount = query.Count();

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var items = query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var result = new CustomAuthPagedResult<CustomAuthClient>
        {
            Items = items,
            TotalCount = totalCount
        };

        return Task.FromResult(result);
    }

    /// <inheritdoc/>
    public Task StoreAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        _clients[client.ClientId] = client;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        _clients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}
