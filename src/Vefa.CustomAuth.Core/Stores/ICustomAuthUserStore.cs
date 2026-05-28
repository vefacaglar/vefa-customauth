namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines host-owned user lookup and credential validation operations.
/// </summary>
public interface ICustomAuthUserStore
{
    /// <summary>
    /// Validates user credentials and returns user information when the credentials are valid.
    /// </summary>
    /// <param name="userName">The submitted user name.</param>
    /// <param name="password">The submitted password.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The user information when authentication succeeds; otherwise null.</returns>
    Task<CustomAuthUserInfo?> ValidateCredentialsAsync(string userName, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a user by its stable subject identifier.
    /// </summary>
    /// <param name="userId">The stable user identifier.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The user information when found; otherwise null.</returns>
    Task<CustomAuthUserInfo?> FindByIdAsync(string userId, CancellationToken cancellationToken = default);
}
