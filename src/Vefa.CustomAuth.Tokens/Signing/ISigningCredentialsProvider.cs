using Microsoft.IdentityModel.Tokens;

namespace Vefa.CustomAuth.Tokens.Signing;

/// <summary>
/// Provides signing credentials and public JSON Web Keys for token issuance and discovery.
/// </summary>
public interface ISigningCredentialsProvider
{
    /// <summary>
    /// Gets the active signing credentials used for newly issued tokens.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The active signing credentials.</returns>
    Task<SigningCredentials> GetActiveAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the public JSON Web Key Set exposed by the discovery endpoint.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The public JSON Web Keys.</returns>
    Task<IReadOnlyList<JsonWebKey>> GetJsonWebKeySetAsync(CancellationToken cancellationToken = default);
}
