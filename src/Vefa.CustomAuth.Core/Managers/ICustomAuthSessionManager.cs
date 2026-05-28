using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for managing user sessions (SSO).
/// </summary>
public interface ICustomAuthSessionManager
{
    /// <summary>
    /// Finds an active or historical session by its session ID.
    /// </summary>
    /// <param name="sessionId">The session ID.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The session if found, otherwise null.</returns>
    Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a paged list of sessions with optional search.
    /// </summary>
    /// <param name="request">The paged request parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paged result of sessions.</returns>
    Task<CustomAuthPagedResult<CustomAuthSession>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and registers a new user session.
    /// </summary>
    /// <param name="session">The session to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CreateAsync(CustomAuthSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes an active user session by its ID.
    /// </summary>
    /// <param name="sessionId">The session ID to revoke.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeAsync(Guid sessionId, CancellationToken cancellationToken = default);
}
