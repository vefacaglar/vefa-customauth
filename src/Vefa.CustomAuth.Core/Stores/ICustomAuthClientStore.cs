using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

public interface ICustomAuthClientStore
{
    Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);
}
