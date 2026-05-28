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

        ValidateClient(client);

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

        ValidateClient(client);

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

    private static void ValidateClient(CustomAuthClient client)
    {
        if (client.RedirectUris == null || client.RedirectUris.Count == 0)
        {
            throw new ArgumentException("At least one redirect URI is required.", nameof(client));
        }

        foreach (var uriString in client.RedirectUris)
        {
            ValidateRedirectUri(uriString, "Redirect URI", nameof(client));
        }

        if (client.PostLogoutRedirectUris != null)
        {
            foreach (var uriString in client.PostLogoutRedirectUris)
            {
                ValidateRedirectUri(uriString, "Post logout redirect URI", nameof(client));
            }
        }

        if (client.AllowRefreshTokens
            && (client.AllowedScopes == null || !client.AllowedScopes.Contains("offline_access", StringComparer.Ordinal)))
        {
            throw new ArgumentException("Clients that allow refresh tokens must include the offline_access scope.", nameof(client));
        }
    }

    private static void ValidateRedirectUri(string uriString, string displayName, string paramName)
    {
        if (string.IsNullOrWhiteSpace(uriString))
        {
            throw new ArgumentException($"{displayName} cannot be empty.", paramName);
        }

        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"{displayName} '{uriString}' must be a valid absolute URI.", paramName);
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException($"{displayName} '{uriString}' must not contain a fragment.", paramName);
        }

        var isLoopback = uri.Host == "localhost" || uri.Host == "127.0.0.1" || uri.Host == "[::1]";

        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            if (!isLoopback)
            {
                throw new ArgumentException($"{displayName} '{uriString}' must use HTTPS unless it is a loopback address.", paramName);
            }
            
            if (!string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"{displayName} '{uriString}' must use HTTPS or HTTP (for loopback only).", paramName);
            }
        }
    }
}
