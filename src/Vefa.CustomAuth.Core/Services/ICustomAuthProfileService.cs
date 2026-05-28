using System.Threading;
using System.Threading.Tasks;

namespace Vefa.CustomAuth.Core.Services;

/// <summary>
/// Provides an extensibility point to dynamically inject claims into tokens and check if a user is currently active.
/// </summary>
public interface ICustomAuthProfileService
{
    /// <summary>
    /// Gets the profile data (claims) for the user to be included in tokens and userinfo.
    /// Modify <see cref="CustomAuthProfileContext.Claims"/> to add custom claims.
    /// </summary>
    /// <param name="context">The profile context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    Task GetProfileDataAsync(CustomAuthProfileContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the user is still allowed to receive tokens.
    /// Return false to reject the token request (e.g. if the user was locked out or deleted).
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>True if the user is active and can receive tokens; otherwise, false.</returns>
    Task<bool> IsUserActiveAsync(string userId, CancellationToken cancellationToken = default);
}
