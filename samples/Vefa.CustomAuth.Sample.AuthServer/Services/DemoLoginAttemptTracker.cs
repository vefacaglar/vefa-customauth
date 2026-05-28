using System.Collections.Concurrent;
using Vefa.CustomAuth.Core.Services;

namespace Vefa.CustomAuth.Sample.AuthServer.Services;

/// <summary>
/// A simple in-memory brute-force lockout tracker for the sample auth server. It locks an
/// account after a configurable number of consecutive failed attempts for a fixed duration.
/// This demonstrates the host-owned <see cref="ICustomAuthLoginAttemptTracker"/> extension point;
/// a production host should back this with a durable, distributed store (e.g. Redis or a database)
/// so the lockout survives restarts and is shared across instances.
/// </summary>
public sealed class DemoLoginAttemptTracker : ICustomAuthLoginAttemptTracker
{
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(5);

    private readonly TimeProvider _timeProvider;
    private readonly ILogger<DemoLoginAttemptTracker> _logger;
    private readonly ConcurrentDictionary<string, AttemptState> _attempts = new(StringComparer.OrdinalIgnoreCase);

    public DemoLoginAttemptTracker(TimeProvider timeProvider, ILogger<DemoLoginAttemptTracker> logger)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<bool> IsBlockedAsync(string userName, CancellationToken cancellationToken = default)
    {
        if (_attempts.TryGetValue(userName, out var state)
            && state.LockedUntil is { } lockedUntil
            && lockedUntil > _timeProvider.GetUtcNow())
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public Task RecordSuccessAsync(string userName, CancellationToken cancellationToken = default)
    {
        _attempts.TryRemove(userName, out _);
        return Task.CompletedTask;
    }

    public Task RecordFailureAsync(string userName, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var state = _attempts.AddOrUpdate(
            userName,
            _ => new AttemptState { FailedCount = 1 },
            (_, existing) =>
            {
                // A lockout that has already elapsed resets the counter.
                if (existing.LockedUntil is { } until && until <= now)
                {
                    return new AttemptState { FailedCount = 1 };
                }

                existing.FailedCount++;
                return existing;
            });

        if (state.FailedCount >= MaxFailedAttempts && state.LockedUntil is null)
        {
            state.LockedUntil = now.Add(LockoutDuration);
            _logger.LogWarning(
                "Account '{UserName}' locked out after {FailedCount} failed attempts until {LockedUntil:o}.",
                userName,
                state.FailedCount,
                state.LockedUntil);
        }

        return Task.CompletedTask;
    }

    private sealed class AttemptState
    {
        public int FailedCount { get; set; }

        public DateTimeOffset? LockedUntil { get; set; }
    }
}
