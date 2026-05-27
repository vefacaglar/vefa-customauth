using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthClientStore"/>.
/// </summary>
/// <typeparam name="TContext">The DbContext type.</typeparam>
public sealed class EfCustomAuthClientStore<TContext> : ICustomAuthClientStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new client store.
    /// </summary>
    /// <param name="context">The DbContext instance.</param>
    public EfCustomAuthClientStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        return _context.Set<CustomAuthClient>()
            .AsNoTracking()
            .SingleOrDefaultAsync(client => client.ClientId == clientId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var query = _context.Set<CustomAuthClient>()
            .AsNoTracking()
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var search = request.Search;
            query = query.Where(c => c.ClientId.Contains(search) || (c.DisplayName != null && c.DisplayName.Contains(search)));
        }

        query = query.OrderBy(c => c.ClientId);

        var totalCount = await query.CountAsync(cancellationToken).ConfigureAwait(false);

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthClient>
        {
            Items = items,
            TotalCount = totalCount
        };
    }

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        var exists = await _context.Set<CustomAuthClient>()
            .AnyAsync(c => c.ClientId == client.ClientId, cancellationToken)
            .ConfigureAwait(false);

        if (exists)
        {
            _context.Set<CustomAuthClient>().Update(client);
        }
        else
        {
            _context.Set<CustomAuthClient>().Add(client);
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var client = await _context.Set<CustomAuthClient>()
            .SingleOrDefaultAsync(c => c.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        if (client is not null)
        {
            _context.Set<CustomAuthClient>().Remove(client);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
