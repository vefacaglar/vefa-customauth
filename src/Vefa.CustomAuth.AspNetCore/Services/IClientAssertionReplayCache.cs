namespace Vefa.CustomAuth.AspNetCore.Services;

/// <summary>
/// Tracks consumed <c>private_key_jwt</c> client-assertion identifiers (<c>jti</c>) so a captured
/// assertion cannot be replayed within its lifetime. The default implementation is per-instance;
/// hosts running multiple instances should provide a distributed implementation.
/// </summary>
public interface IClientAssertionReplayCache
{
    /// <summary>
    /// Atomically records an assertion's <c>jti</c> as consumed.
    /// </summary>
    /// <param name="clientId">The authenticating client identifier.</param>
    /// <param name="jti">The assertion's unique identifier.</param>
    /// <param name="expiresAt">The assertion's expiry; the entry need not be retained past this time.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><c>true</c> when the jti was newly registered; <c>false</c> when it was already seen (a replay).</returns>
    Task<bool> TryRegisterAsync(string clientId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
