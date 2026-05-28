using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines persistence operations for token signing keys.
/// </summary>
public interface ICustomAuthSigningKeyStore
{
    /// <summary>
    /// Gets the active signing key used for newly issued tokens.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The active signing key if found; otherwise null.</returns>
    Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all signing keys.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A read-only list of signing keys.</returns>
    Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a signing key.
    /// </summary>
    /// <param name="key">The signing key to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default);
}
