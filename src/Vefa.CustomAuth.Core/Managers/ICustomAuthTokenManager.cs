using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for managing authorization codes and refresh tokens.
/// </summary>
public interface ICustomAuthTokenManager
{
    /// <summary>
    /// Validates and stores a newly issued authorization code.
    /// </summary>
    /// <param name="code">The authorization code to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAuthorizationCodeAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an authorization code by its SHA-256 hash.
    /// </summary>
    /// <param name="codeHash">The SHA-256 hash of the code.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authorization code if found, otherwise null.</returns>
    Task<CustomAuthAuthorizationCode?> FindAuthorizationCodeByHashAsync(string codeHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically marks an authorization code as consumed. The underlying store performs a
    /// conditional update so two concurrent token exchanges cannot both succeed for the same code.
    /// </summary>
    /// <param name="id">The unique identifier of the authorization code.</param>
    /// <param name="consumedAt">The timestamp when it was consumed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><c>true</c> when this call transitioned the code from unconsumed to consumed; <c>false</c> if the code was already consumed or missing.</returns>
    Task<bool> MarkAuthorizationCodeConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates and stores a newly issued refresh token.
    /// </summary>
    /// <param name="token">The refresh token model.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreRefreshTokenAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a refresh token by its SHA-256 hash.
    /// </summary>
    /// <param name="tokenHash">The SHA-256 hash of the refresh token.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The refresh token model if found, otherwise null.</returns>
    Task<CustomAuthRefreshToken?> FindRefreshTokenByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a paged list of refresh tokens with optional search.
    /// </summary>
    /// <param name="request">The paged request parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paged result of refresh tokens.</returns>
    Task<CustomAuthPagedResult<CustomAuthRefreshToken>> GetRefreshTokensPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically marks a refresh token as consumed during rotation. The underlying store
    /// performs a conditional update so two concurrent rotations cannot both succeed for the same token.
    /// </summary>
    /// <param name="id">The unique identifier of the refresh token.</param>
    /// <param name="consumedAt">The timestamp when it was consumed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><c>true</c> when this call transitioned the token from unconsumed to consumed; <c>false</c> if the token was already consumed or missing.</returns>
    Task<bool> MarkRefreshTokenConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token immediately.
    /// </summary>
    /// <param name="id">The unique identifier of the refresh token.</param>
    /// <param name="revokedAt">The timestamp when it was revoked.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeRefreshTokenAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token immediately, and if session-bound, also revokes its entire rotation chain.
    /// </summary>
    /// <param name="token">The refresh token to revoke.</param>
    /// <param name="revokedAt">The timestamp when it was revoked.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RevokeRefreshTokenChainAsync(CustomAuthRefreshToken token, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records refresh token reuse and revokes the related refresh token chain when possible.
    /// </summary>
    /// <param name="token">The reused refresh token.</param>
    /// <param name="detectedAt">The timestamp when reuse was detected.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task HandleRefreshTokenReuseAsync(CustomAuthRefreshToken token, DateTimeOffset detectedAt, CancellationToken cancellationToken = default);
}
