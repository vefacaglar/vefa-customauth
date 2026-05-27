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

    public Task<CustomAuthPagedResult<CustomAuthSession>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _sessions.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(s => s.UserId.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        query = query.OrderByDescending(s => s.CreatedAt);

        var totalCount = query.Count();
        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;
        var items = query.Skip((page - 1) * pageSize).Take(pageSize).ToList();

        return Task.FromResult(new CustomAuthPagedResult<CustomAuthSession> { Items = items, TotalCount = totalCount });
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
