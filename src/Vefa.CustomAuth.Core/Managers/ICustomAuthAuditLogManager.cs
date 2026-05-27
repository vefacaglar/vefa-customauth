using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Defines business operations for auditing and tracking security actions.
/// </summary>
public interface ICustomAuthAuditLogManager
{
    /// <summary>
    /// Registers a new security audit log entry.
    /// </summary>
    /// <param name="log">The audit log details.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a paginated list of audit log entries.
    /// </summary>
    /// <param name="request">The pagination and search parameters.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A paginated list of audit logs.</returns>
    Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default);
}
