using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines persistence operations for SSO sessions.
/// </summary>
public interface ICustomAuthSessionStore
{
    /// <summary>
    /// Finds a session by its identifier.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The session if found; otherwise null.</returns>
    Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paged list of sessions.
    /// </summary>
    /// <param name="request">The paged request parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paged result containing sessions.</returns>
    Task<CustomAuthPagedResult<CustomAuthSession>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a new or updated session.
    /// </summary>
    /// <param name="session">The session to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a session.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <param name="revokedAt">The timestamp when the session was revoked.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
