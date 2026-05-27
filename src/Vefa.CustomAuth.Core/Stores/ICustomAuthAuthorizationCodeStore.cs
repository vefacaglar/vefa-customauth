using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

public interface ICustomAuthAuthorizationCodeStore
{
    Task StoreAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default);
    Task<CustomAuthAuthorizationCode?> FindByHashAsync(string codeHash, CancellationToken cancellationToken = default);
    Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default);
}
