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
/// In-memory implementation of <see cref="ICustomAuthScopeStore"/>.
/// Intended for samples, integration tests, and local development.
/// </summary>
public sealed class InMemoryScopeStore : ICustomAuthScopeStore
{
    private readonly ConcurrentDictionary<string, CustomAuthScope> _scopes = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryScopeStore"/> class.
    /// </summary>
    /// <param name="initialScopes">Optional list of scopes to seed.</param>
    public InMemoryScopeStore(IEnumerable<CustomAuthScope>? initialScopes = null)
    {
        if (initialScopes != null)
        {
            foreach (var scope in initialScopes)
            {
                if (scope.Name != null)
                {
                    _scopes[scope.Name] = scope;
                }
            }
        }
    }

    /// <inheritdoc/>
    public Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _scopes.TryGetValue(name, out var scope);
        return Task.FromResult(scope);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<CustomAuthScope> result = _scopes.Values.ToList();
        return Task.FromResult(result);
    }

    /// <inheritdoc/>
    public Task StoreAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(scope.Name);

        _scopes[scope.Name] = scope;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        _scopes.TryRemove(name, out _);
        return Task.CompletedTask;
    }
}
