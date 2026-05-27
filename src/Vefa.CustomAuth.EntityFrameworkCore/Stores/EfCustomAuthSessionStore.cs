using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthSessionStore"/>.
/// </summary>
public sealed class EfCustomAuthSessionStore<TContext> : ICustomAuthSessionStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new session store.
    /// </summary>
    public EfCustomAuthSessionStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default)
        => _context.Set<CustomAuthSession>()
            .AsNoTracking()
            .SingleOrDefaultAsync(session => session.Id == sessionId, cancellationToken);

    /// <inheritdoc />
    public async Task<CustomAuthPagedResult<CustomAuthSession>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _context.Set<CustomAuthSession>().AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(s => s.UserId.Contains(search));
        }

        query = query.OrderByDescending(s => s.CreatedAt);

        var totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken).ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthSession> { Items = items, TotalCount = totalCount };
    }

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);

        _context.Set<CustomAuthSession>().Add(session);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RevokeAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var session = await _context.Set<CustomAuthSession>()
            .SingleOrDefaultAsync(item => item.Id == sessionId, cancellationToken)
            .ConfigureAwait(false);

        if (session is null)
        {
            return;
        }

        session.RevokedAt = revokedAt;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
