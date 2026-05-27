using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthSigningKeyManager"/> interface.
/// </summary>
public sealed class CustomAuthSigningKeyManager : ICustomAuthSigningKeyManager
{
    private readonly ICustomAuthSigningKeyStore _keyStore;
    private readonly ICustomAuthAuditLogStore _auditLogStore;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthSigningKeyManager"/> class.
    /// </summary>
    /// <param name="keyStore">The signing key store.</param>
    /// <param name="auditLogStore">The audit log store.</param>
    /// <param name="timeProvider">The time provider.</param>
    public CustomAuthSigningKeyManager(
        ICustomAuthSigningKeyStore keyStore,
        ICustomAuthAuditLogStore auditLogStore,
        TimeProvider timeProvider)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        return _keyStore.GetActiveAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return _keyStore.GetAllAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(key.KeyId);

        await _keyStore.StoreAsync(key, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "SigningKeyRotated",
            TargetType = "SigningKey",
            TargetId = key.KeyId,
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }
}
