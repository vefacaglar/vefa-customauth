using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthAuditLogStore"/>.
/// </summary>
/// <typeparam name="TContext">The DbContext type.</typeparam>
public sealed class EfCustomAuthAuditLogStore<TContext> : ICustomAuthAuditLogStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfCustomAuthAuditLogStore{TContext}"/> class.
    /// </summary>
    /// <param name="context">The DbContext instance.</param>
    public EfCustomAuthAuditLogStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(log);
        if (log.Id == Guid.Empty)
        {
            throw new ArgumentException("Log ID cannot be empty.", nameof(log));
        }

        _context.Set<CustomAuthAuditLog>().Add(log);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _context.Set<CustomAuthAuditLog>()
            .AsNoTracking()
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(l =>
                l.Action.Contains(search) ||
                (l.TargetType != null && l.TargetType.Contains(search)) ||
                (l.TargetId != null && l.TargetId.Contains(search)) ||
                (l.ActorUserId != null && l.ActorUserId.Contains(search))
            );
        }

        query = query.OrderByDescending(l => l.Timestamp);

        var totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthAuditLog>
        {
            Items = items,
            TotalCount = totalCount
        };
    }
}
