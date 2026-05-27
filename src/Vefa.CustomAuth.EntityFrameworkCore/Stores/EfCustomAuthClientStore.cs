using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthClientStore"/>.
/// </summary>
public sealed class EfCustomAuthClientStore<TContext> : ICustomAuthClientStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new client store.
    /// </summary>
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
}
