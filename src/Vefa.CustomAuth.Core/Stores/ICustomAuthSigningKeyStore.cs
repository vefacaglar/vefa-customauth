using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

public interface ICustomAuthSigningKeyStore
{
    Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default);
    Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default);
}
