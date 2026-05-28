using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Services;

namespace Vefa.CustomAuth.EntityFrameworkCore.Services;

/// <summary>
/// EF Core implementation of <see cref="ICustomAuthCleanupService"/>.
/// </summary>
/// <typeparam name="TContext">The DbContext type.</typeparam>
public sealed class EfCustomAuthCleanupService<TContext> : ICustomAuthCleanupService
    where TContext : DbContext
{
    private readonly TContext _context;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="EfCustomAuthCleanupService{TContext}"/> class.
    /// </summary>
    /// <param name="context">The DbContext instance.</param>
    /// <param name="timeProvider">The time provider.</param>
    public EfCustomAuthCleanupService(TContext context, TimeProvider timeProvider)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public async Task CleanupAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var provider = _context.Database.ProviderName;
        var useMemoryCleanup = provider == "Microsoft.EntityFrameworkCore.InMemory"
            || provider == "Microsoft.EntityFrameworkCore.Sqlite";

        var codesSet = _context.Set<CustomAuthAuthorizationCode>();
        var tokensSet = _context.Set<CustomAuthRefreshToken>();
        var sessionsSet = _context.Set<CustomAuthSession>();

        if (useMemoryCleanup)
        {
            var hasChanges = false;

            // 1. Clear expired or consumed authorization codes
            var expiredCodes = await codesSet.ToListAsync(cancellationToken).ConfigureAwait(false);
            var toRemoveCodes = expiredCodes.Where(c => c.ExpiresAt <= now || c.ConsumedAt != null).ToList();
            if (toRemoveCodes.Count > 0)
            {
                codesSet.RemoveRange(toRemoveCodes);
                hasChanges = true;
            }

            // 2. Clear expired refresh tokens
            var expiredTokens = await tokensSet.ToListAsync(cancellationToken).ConfigureAwait(false);
            var toRemoveTokens = expiredTokens.Where(t => t.ExpiresAt <= now).ToList();
            if (toRemoveTokens.Count > 0)
            {
                tokensSet.RemoveRange(toRemoveTokens);
                hasChanges = true;
            }

            // 3. Clear expired or revoked sessions
            var expiredSessions = await sessionsSet.ToListAsync(cancellationToken).ConfigureAwait(false);
            var toRemoveSessions = expiredSessions.Where(s => s.ExpiresAt <= now || s.RevokedAt != null).ToList();
            if (toRemoveSessions.Count > 0)
            {
                sessionsSet.RemoveRange(toRemoveSessions);
                hasChanges = true;
            }

            if (hasChanges)
            {
                await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            // For relational production providers (PostgreSQL, SQL Server, MySQL), execute direct bulk deletions
            await codesSet
                .Where(c => c.ExpiresAt <= now || c.ConsumedAt != null)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);

            await tokensSet
                .Where(t => t.ExpiresAt <= now)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);

            await sessionsSet
                .Where(s => s.ExpiresAt <= now || s.RevokedAt != null)
                .ExecuteDeleteAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
