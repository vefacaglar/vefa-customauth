using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

public interface ICustomAuthRefreshTokenStore
{
    Task StoreAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default);
    Task<CustomAuthRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
    Task RevokeAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
