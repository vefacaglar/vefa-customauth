using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthClientManager"/> interface.
/// </summary>
public sealed class CustomAuthClientManager : ICustomAuthClientManager
{
    private readonly ICustomAuthClientStore _clientStore;
    private readonly ICustomAuthAuditLogStore _auditLogStore;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthClientManager"/> class.
    /// </summary>
    /// <param name="clientStore">The client store.</param>
    /// <param name="auditLogStore">The audit log store.</param>
    /// <param name="timeProvider">The system or test time provider.</param>
    public CustomAuthClientManager(
        ICustomAuthClientStore clientStore,
        ICustomAuthAuditLogStore auditLogStore,
        TimeProvider timeProvider)
    {
        _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        return _clientStore.FindByClientIdAsync(clientId, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _clientStore.GetPagedAsync(request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task CreateAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        // Perform basic validations
        if (client.RedirectUris == null || client.RedirectUris.Count == 0)
        {
            throw new ArgumentException("At least one redirect URI is required.", nameof(client));
        }

        await _clientStore.StoreAsync(client, cancellationToken).ConfigureAwait(false);

        // Audit log client creation
        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ClientCreated",
            TargetType = "Client",
            TargetId = client.ClientId,
            Timestamp = _timeProvider.GetUtcNow(),
            Metadata = $"{{\"DisplayName\":\"{client.DisplayName}\"}}"
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task UpdateAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        if (client.RedirectUris == null || client.RedirectUris.Count == 0)
        {
            throw new ArgumentException("At least one redirect URI is required.", nameof(client));
        }

        await _clientStore.StoreAsync(client, cancellationToken).ConfigureAwait(false);

        // Audit log client update
        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ClientUpdated",
            TargetType = "Client",
            TargetId = client.ClientId,
            Timestamp = _timeProvider.GetUtcNow(),
            Metadata = $"{{\"DisplayName\":\"{client.DisplayName}\"}}"
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        await _clientStore.DeleteAsync(clientId, cancellationToken).ConfigureAwait(false);

        // Audit log client deletion
        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "ClientDeleted",
            TargetType = "Client",
            TargetId = clientId,
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }
}
