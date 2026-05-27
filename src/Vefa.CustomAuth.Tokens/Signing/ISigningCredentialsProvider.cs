using Microsoft.IdentityModel.Tokens;

namespace Vefa.CustomAuth.Tokens.Signing;

public interface ISigningCredentialsProvider
{
    Task<SigningCredentials> GetActiveAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<JsonWebKey>> GetJsonWebKeySetAsync(CancellationToken cancellationToken = default);
}
