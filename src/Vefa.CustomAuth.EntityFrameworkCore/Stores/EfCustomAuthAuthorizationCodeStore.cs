using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthAuthorizationCodeStore"/>.
/// </summary>
public sealed class EfCustomAuthAuthorizationCodeStore<TContext> : ICustomAuthAuthorizationCodeStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Creates a new authorization code store.
    /// </summary>
    public EfCustomAuthAuthorizationCodeStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc />
    public async Task StoreAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);

        _context.Set<CustomAuthAuthorizationCode>().Add(code);
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<CustomAuthAuthorizationCode?> FindByHashAsync(string codeHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(codeHash);

        return _context.Set<CustomAuthAuthorizationCode>()
            .AsNoTracking()
            .SingleOrDefaultAsync(code => code.CodeHash == codeHash, cancellationToken);
    }

    /// <inheritdoc />
    public async Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var code = await _context.Set<CustomAuthAuthorizationCode>()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken)
            .ConfigureAwait(false);

        if (code is null)
        {
            return;
        }

        code.ConsumedAt = consumedAt;
        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
