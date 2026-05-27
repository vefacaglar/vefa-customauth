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
/// In-memory implementation of <see cref="ICustomAuthAuditLogStore"/>.
/// Intended for samples, integration tests, and local development.
/// </summary>
public sealed class InMemoryAuditLogStore : ICustomAuthAuditLogStore
{
    private readonly ConcurrentDictionary<Guid, CustomAuthAuditLog> _logs = new();

    /// <inheritdoc/>
    public Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(log);
        if (log.Id == Guid.Empty)
        {
            throw new ArgumentException("Audit log ID cannot be empty.", nameof(log));
        }

        _logs[log.Id] = log;
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _logs.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(l =>
                l.Action.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                (l.TargetType != null && l.TargetType.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
                (l.TargetId != null && l.TargetId.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
                (l.ActorUserId != null && l.ActorUserId.Contains(search, StringComparison.OrdinalIgnoreCase))
            );
        }

        // Sort descending by Timestamp by default for audit logs
        query = query.OrderByDescending(l => l.Timestamp);

        var totalCount = query.Count();

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var items = query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var result = new CustomAuthPagedResult<CustomAuthAuditLog>
        {
            Items = items,
            TotalCount = totalCount
        };

        return Task.FromResult(result);
    }
}
