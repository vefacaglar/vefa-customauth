using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthAuthorizationCodeStore"/>.
/// Codes are looked up by their hashed form; the raw code is never stored.
/// </summary>
public sealed class InMemoryAuthorizationCodeStore : ICustomAuthAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, CustomAuthAuthorizationCode> _codesByHash = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Guid, CustomAuthAuthorizationCode> _codesById = new();

    public Task StoreAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        _codesByHash[code.CodeHash] = code;
        _codesById[code.Id] = code;
        return Task.CompletedTask;
    }

    public Task<CustomAuthAuthorizationCode?> FindByHashAsync(string codeHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(codeHash);
        _codesByHash.TryGetValue(codeHash, out var code);
        return Task.FromResult(code);
    }

    public Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        if (_codesById.TryGetValue(id, out var code))
        {
            code.ConsumedAt = consumedAt;
        }

        return Task.CompletedTask;
    }
}
