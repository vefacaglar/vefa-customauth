using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthAuditLogManager"/> interface.
/// </summary>
public sealed class CustomAuthAuditLogManager : ICustomAuthAuditLogManager
{
    private readonly ICustomAuthAuditLogStore _auditLogStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthAuditLogManager"/> class.
    /// </summary>
    /// <param name="auditLogStore">The audit log store.</param>
    public CustomAuthAuditLogManager(ICustomAuthAuditLogStore auditLogStore)
    {
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
    }

    /// <inheritdoc/>
    public Task StoreAsync(CustomAuthAuditLog log, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(log);
        if (log.Id == Guid.Empty)
        {
            throw new ArgumentException("Log ID cannot be empty.", nameof(log));
        }
        ArgumentException.ThrowIfNullOrEmpty(log.Action);
        ArgumentException.ThrowIfNullOrEmpty(log.TargetType);
        ArgumentException.ThrowIfNullOrEmpty(log.TargetId);

        return _auditLogStore.StoreAsync(log, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthAuditLog>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _auditLogStore.GetPagedAsync(request, cancellationToken);
    }
}
