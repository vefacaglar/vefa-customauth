using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthRefreshTokenStore"/>.
/// </summary>
public sealed class EfCustomAuthRefreshTokenStore<TContext> : ICustomAuthRefreshTokenStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new refresh token store.
    /// </summary>
    public EfCustomAuthRefreshTokenStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        _context.Set<CustomAuthRefreshToken>().Add(token);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<CustomAuthRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);

        return _context.Set<CustomAuthRefreshToken>()
            .AsNoTracking()
            .SingleOrDefaultAsync(token => token.TokenHash == tokenHash, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<CustomAuthPagedResult<CustomAuthRefreshToken>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _context.Set<CustomAuthRefreshToken>().AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(t => t.ClientId.Contains(search) || t.UserId.Contains(search));
        }

        query = query.OrderByDescending(t => t.CreatedAt);

        var totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;
        var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken).ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthRefreshToken> { Items = items, TotalCount = totalCount };
    }

    /// <inheritdoc />
    public async Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var token = await _context.Set<CustomAuthRefreshToken>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken)
            .ConfigureAwait(false);

        if (token is null)
        {
            return;
        }

        token.ConsumedAt = consumedAt;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RevokeAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var token = await _context.Set<CustomAuthRefreshToken>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken)
            .ConfigureAwait(false);

        if (token is null)
        {
            return;
        }

        token.RevokedAt = revokedAt;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
