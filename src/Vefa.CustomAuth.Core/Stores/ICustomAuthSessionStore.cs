using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

public interface ICustomAuthSessionStore
{
    Task<CustomAuthSession?> FindAsync(Guid sessionId, CancellationToken cancellationToken = default);
    Task StoreAsync(CustomAuthSession session, CancellationToken cancellationToken = default);
    Task RevokeAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default);
}
