using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthScopeManager"/> interface.
/// </summary>
public sealed class CustomAuthScopeManager : ICustomAuthScopeManager
{
    private readonly ICustomAuthScopeStore _scopeStore;
    private readonly ICustomAuthAuditLogStore _auditLogStore;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthScopeManager"/> class.
    /// </summary>
    /// <param name="scopeStore">The scope store.</param>
    /// <param name="auditLogStore">The audit log store.</param>
    /// <param name="timeProvider">The system or test time provider.</param>
    public CustomAuthScopeManager(
        ICustomAuthScopeStore scopeStore,
        ICustomAuthAuditLogStore auditLogStore,
        TimeProvider timeProvider)
    {
        _scopeStore = scopeStore ?? throw new ArgumentNullException(nameof(scopeStore));
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public Task<CustomAuthScope?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        return _scopeStore.FindByNameAsync(name, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<CustomAuthScope>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return _scopeStore.GetAllAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task CreateAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(scope.Name);

        await _scopeStore.StoreAsync(scope, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ScopeCreated",
            TargetType = "Scope",
            TargetId = scope.Name,
            Timestamp = _timeProvider.GetUtcNow(),
            Metadata = $"{{\"DisplayName\":\"{scope.DisplayName}\"}}"
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(CustomAuthScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(scope.Name);

        await _scopeStore.StoreAsync(scope, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ScopeUpdated",
            TargetType = "Scope",
            TargetId = scope.Name,
            Timestamp = _timeProvider.GetUtcNow(),
            Metadata = $"{{\"DisplayName\":\"{scope.DisplayName}\"}}"
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        await _scopeStore.DeleteAsync(name, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ScopeDeleted",
            TargetType = "Scope",
            TargetId = name,
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }
}
