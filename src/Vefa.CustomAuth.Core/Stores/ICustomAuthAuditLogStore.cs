using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Defines persistence operations for security audit logs.
/// </summary>
public interface ICustomAuthAuditLogStore
{
    /// <summary>
    /// Persists a new audit log entry.
    /// </summary>
    /// <param name="log">The audit log entry to persist.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paginated list of audit logs.
    /// </summary>
    /// <param name="request">The pagination request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paginated result containing audit log entries.</returns>
    Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);
}
