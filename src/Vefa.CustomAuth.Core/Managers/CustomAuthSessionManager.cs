using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthSessionManager"/> interface.
/// </summary>
public sealed class CustomAuthSessionManager : ICustomAuthSessionManager
{
    private readonly ICustomAuthSessionStore _sessionStore;
    private readonly ICustomAuthAuditLogStore _auditLogStore;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthSessionManager"/> class.
    /// </summary>
    /// <param name="sessionStore">The session store.</param>
    /// <param name="auditLogStore">The audit log store.</param>
    /// <param name="timeProvider">The time provider.</param>
    public CustomAuthSessionManager(
        ICustomAuthSessionStore sessionStore,
        ICustomAuthAuditLogStore auditLogStore,
        TimeProvider timeProvider)
    {
        _sessionStore = sessionStore ?? throw new ArgumentNullException(nameof(sessionStore));
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        }

        return _sessionStore.FindAsync(sessionId, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthSession>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _sessionStore.GetPagedAsync(request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task CreateAsync(CustomAuthSession session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (session.Id == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(session));
        }

        await _sessionStore.StoreAsync(session, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "SessionCreated",
            TargetType = "Session",
            TargetId = session.Id.ToString(),
            ActorUserId = session.UserId,
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task RevokeAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        }

        var now = _timeProvider.GetUtcNow();
        var session = await _sessionStore.FindAsync(sessionId, cancellationToken).ConfigureAwait(false);

        await _sessionStore.RevokeAsync(sessionId, now, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "SessionRevoked",
            TargetType = "Session",
            TargetId = sessionId.ToString(),
            ActorUserId = session?.UserId,
            Timestamp = now
        }, cancellationToken).ConfigureAwait(false);
    }
}
