using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines persistence operations for OAuth2 authorization codes.
/// </summary>
public interface ICustomAuthAuthorizationCodeStore
{
    /// <summary>
    /// Persists a new authorization code.
    /// </summary>
    /// <param name="code">The authorization code to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an authorization code by its stored hash.
    /// </summary>
    /// <param name="codeHash">The hashed authorization code.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The authorization code if found; otherwise null.</returns>
    Task<CustomAuthAuthorizationCode?> FindByHashAsync(string codeHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks an authorization code as consumed.
    /// </summary>
    /// <param name="id">The authorization code identifier.</param>
    /// <param name="consumedAt">The timestamp when the code was consumed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
}
