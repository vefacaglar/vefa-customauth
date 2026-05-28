using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Services;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// A default no-op implementation of <see cref="ICustomAuthLoginAttemptTracker"/>.
/// </summary>
internal sealed class DefaultLoginAttemptTracker : ICustomAuthLoginAttemptTracker
{
    /// <inheritdoc/>
    public Task<bool> IsBlockedAsync(string userName, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(false);
    }

    /// <inheritdoc/>
    public Task RecordSuccessAsync(string userName, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task RecordFailureAsync(string userName, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}
