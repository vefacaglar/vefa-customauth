using System.Threading;
using System.Threading.Tasks;

namespace Vefa.CustomAuth.Core.Services;

/// <summary>
/// Allows host applications to track login attempts to implement account lockout or brute-force protections.
/// </summary>
public interface ICustomAuthLoginAttemptTracker
{
    /// <summary>
    /// Checks if the login attempt should be blocked (e.g. account is locked out).
    /// </summary>
    /// <param name="userName">The username attempting to log in.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the attempt is blocked; otherwise, false.</returns>
    Task<bool> IsBlockedAsync(string userName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a successful login attempt, which should typically reset the attempt counter.
    /// </summary>
    /// <param name="userName">The username that successfully logged in.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RecordSuccessAsync(string userName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a failed login attempt.
    /// </summary>
    /// <param name="userName">The username that failed to log in.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task RecordFailureAsync(string userName, CancellationToken cancellationToken = default);
}
