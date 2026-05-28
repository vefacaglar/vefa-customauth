using Microsoft.Extensions.Caching.Memory;

namespace Vefa.CustomAuth.AspNetCore.Services;

/// <summary>
/// Per-instance <see cref="IClientAssertionReplayCache"/> backed by <see cref="IMemoryCache"/>.
/// Suitable for single-instance deployments; replace with a distributed cache (e.g. Redis) when
/// running multiple instances so a replay is detected across the cluster.
/// </summary>
public sealed class MemoryClientAssertionReplayCache : IClientAssertionReplayCache
{
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();

    public MemoryClientAssertionReplayCache(IMemoryCache cache, TimeProvider timeProvider)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public Task<bool> TryRegisterAsync(string clientId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var key = $"client_assertion_jti:{clientId}:{jti}";

        // Retain slightly past expiry so a replay arriving within the clock-skew window is still caught.
        var retainUntil = expiresAt.AddMinutes(1);
        if (retainUntil <= _timeProvider.GetUtcNow())
        {
            // Already expired; nothing to retain, but treat as newly seen so the caller can proceed
            // to the normal lifetime check (which will reject an expired assertion).
            return Task.FromResult(true);
        }

        lock (_gate)
        {
            if (_cache.TryGetValue(key, out _))
            {
                return Task.FromResult(false);
            }

            _cache.Set(key, true, retainUntil);
            return Task.FromResult(true);
        }
    }
}
