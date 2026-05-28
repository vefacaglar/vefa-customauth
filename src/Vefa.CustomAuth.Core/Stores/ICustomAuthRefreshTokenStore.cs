using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines persistence operations for opaque refresh tokens.
/// </summary>
public interface ICustomAuthRefreshTokenStore
{
    /// <summary>
    /// Persists a new refresh token.
    /// </summary>
    /// <param name="token">The refresh token to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a refresh token by its stored hash.
    /// </summary>
    /// <param name="tokenHash">The hashed refresh token.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The refresh token if found; otherwise null.</returns>
    Task<CustomAuthRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paged list of refresh tokens.
    /// </summary>
    /// <param name="request">The paged request parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paged result containing refresh tokens.</returns>
    Task<CustomAuthPagedResult<CustomAuthRefreshToken>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically marks a refresh token as consumed after rotation, but only when it has
    /// not been consumed yet. Implementations must perform a conditional update so that
    /// concurrent rotation attempts cannot both succeed for the same token.
    /// </summary>
    /// <param name="id">The refresh token identifier.</param>
    /// <param name="consumedAt">The timestamp when the token was consumed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><c>true</c> when this call transitioned the token from unconsumed to consumed; <c>false</c> when the token was already consumed, did not exist, or was claimed by another concurrent request.</returns>
    Task<bool> MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token.
    /// </summary>
    /// <param name="id">The refresh token identifier.</param>
    /// <param name="revokedAt">The timestamp when the token was revoked.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all active refresh tokens associated with an SSO session.
    /// </summary>
    /// <param name="sessionId">The SSO session identifier.</param>
    /// <param name="revokedAt">The timestamp when the tokens were revoked.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeBySessionIdAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
