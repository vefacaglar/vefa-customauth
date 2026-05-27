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

        // 1. Clear expired or consumed authorization codes
        var codesSet = _context.Set<CustomAuthAuthorizationCode>();
        var expiredCodes = await codesSet
            .Where(c => c.ExpiresAt <= now || c.ConsumedAt != null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (expiredCodes.Count > 0)
        {
            codesSet.RemoveRange(expiredCodes);
        }

        // 2. Clear expired refresh tokens
        var tokensSet = _context.Set<CustomAuthRefreshToken>();
        var expiredTokens = await tokensSet
            .Where(t => t.ExpiresAt <= now)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (expiredTokens.Count > 0)
        {
            tokensSet.RemoveRange(expiredTokens);
        }

        // 3. Clear expired or revoked sessions
        var sessionsSet = _context.Set<CustomAuthSession>();
        var expiredSessions = await sessionsSet
            .Where(s => s.ExpiresAt <= now || s.RevokedAt != null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (expiredSessions.Count > 0)
        {
            sessionsSet.RemoveRange(expiredSessions);
        }

        await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
