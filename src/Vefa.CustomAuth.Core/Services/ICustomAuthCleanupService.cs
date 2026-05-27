using System.Threading;
using System.Threading.Tasks;

namespace Vefa.CustomAuth.Core.Services;

/// <summary>
/// Defines operations for cleaning up expired and stale custom authentication records.
/// </summary>
public interface ICustomAuthCleanupService
{
    /// <summary>
    /// Performs a cleanup of expired authorization codes, refresh tokens, and sessions.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CleanupAsync(CancellationToken cancellationToken = default);
}
