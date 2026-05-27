using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Stores.InMemory;

/// <summary>
/// In-memory implementation of <see cref="ICustomAuthSessionStore"/>.
/// </summary>
public sealed class InMemorySessionStore : ICustomAuthSessionStore
{
    private readonly ConcurrentDictionary<Guid, CustomAuthSession> _sessions = new();

    public Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        _sessions.TryGetValue(sessionId, out var session);
        return Task.FromResult(session);
    }

    public Task StoreAsync(CustomAuthSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        _sessions[session.Id] = session;
        return Task.CompletedTask;
    }

    public Task RevokeAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
        {
            session.RevokedAt = revokedAt;
        }

        return Task.CompletedTask;
    }
}
