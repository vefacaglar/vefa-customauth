using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for managing token signing keys.
/// </summary>
public interface ICustomAuthSigningKeyManager
{
    /// <summary>
    /// Gets the currently active signing key.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The active signing key if found, otherwise null.</returns>
    Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all signing keys (active and expired).
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A read-only list of signing keys.</returns>
    Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers a newly generated signing key.
    /// </summary>
    /// <param name="key">The signing key to store.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default);
}
