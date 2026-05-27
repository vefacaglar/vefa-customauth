using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Stores;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthScopeStore"/>.
/// </summary>
/// <typeparam name="TContext">The DbContext type.</typeparam>
public sealed class EfCustomAuthScopeStore<TContext> : ICustomAuthScopeStore
    where TContext : DbContext
{
    private readonly TContext _context;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfCustomAuthScopeStore{TContext}"/> class.
    /// </summary>
    /// <param name="context">The DbContext instance.</param>
    public EfCustomAuthScopeStore(TContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc/>
    public Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return _context.Set<CustomAuthScope>()
            .AsNoTracking()
            .SingleOrDefaultAsync(s => s.Name == name, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.Set<CustomAuthScope>()
            .AsNoTracking()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(scope.Name);

        var exists = await _context.Set<CustomAuthScope>()
            .AnyAsync(s => s.Name == scope.Name, cancellationToken)
            .ConfigureAwait(false);

        if (exists)
        {
            _context.Set<CustomAuthScope>().Update(scope);
        }
        else
        {
            _context.Set<CustomAuthScope>().Add(scope);
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var scope = await _context.Set<CustomAuthScope>()
            .SingleOrDefaultAsync(s => s.Name == name, cancellationToken)
            .ConfigureAwait(false);

        if (scope is not null)
        {
            _context.Set<CustomAuthScope>().Remove(scope);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
