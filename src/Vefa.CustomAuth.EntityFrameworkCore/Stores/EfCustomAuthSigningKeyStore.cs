using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthSigningKeyStore"/>.
/// </summary>
public sealed class EfCustomAuthSigningKeyStore<TContext> : ICustomAuthSigningKeyStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new signing key store.
    /// </summary>
    public EfCustomAuthSigningKeyStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default)
        => _context.Set<CustomAuthSigningKey>()
            .AsNoTracking()
            .SingleOrDefaultAsync(key => key.IsActive && key.RetiredAt == null, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default)
        => await _context.Set<CustomAuthSigningKey>()
            .AsNoTracking()
            .OrderByDescending(key => key.CreatedAt)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        _context.Set<CustomAuthSigningKey>().Add(key);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
