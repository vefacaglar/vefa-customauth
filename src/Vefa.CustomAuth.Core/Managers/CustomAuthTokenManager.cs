using System;
using System.Threading;
using System.Threading.Tasks;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Core.Managers;

/// <summary>
/// Default implementation of the <see cref="ICustomAuthTokenManager"/> interface.
/// </summary>
public sealed class CustomAuthTokenManager : ICustomAuthTokenManager
{
    private readonly ICustomAuthAuthorizationCodeStore _codeStore;
    private readonly ICustomAuthRefreshTokenStore _refreshTokenStore;
    private readonly ICustomAuthAuditLogStore _auditLogStore;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CustomAuthTokenManager"/> class.
    /// </summary>
    /// <param name="codeStore">The authorization code store.</param>
    /// <param name="refreshTokenStore">The refresh token store.</param>
    /// <param name="auditLogStore">The audit log store.</param>
    /// <param name="timeProvider">The time provider.</param>
    public CustomAuthTokenManager(
        ICustomAuthAuthorizationCodeStore codeStore,
        ICustomAuthRefreshTokenStore refreshTokenStore,
        ICustomAuthAuditLogStore auditLogStore,
        TimeProvider timeProvider)
    {
        _codeStore = codeStore ?? throw new ArgumentNullException(nameof(codeStore));
        _refreshTokenStore = refreshTokenStore ?? throw new ArgumentNullException(nameof(refreshTokenStore));
        _auditLogStore = auditLogStore ?? throw new ArgumentNullException(nameof(auditLogStore));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <inheritdoc/>
    public Task StoreAuthorizationCodeAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        if (code.Id == Guid.Empty)
        {
            throw new ArgumentException("Code ID cannot be empty.", nameof(code));
        }
        ArgumentException.ThrowIfNullOrEmpty(code.CodeHash);

        return _codeStore.StoreAsync(code, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthAuthorizationCode?> FindAuthorizationCodeByHashAsync(string codeHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(codeHash);
        return _codeStore.FindByHashAsync(codeHash, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task MarkAuthorizationCodeConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Code ID cannot be empty.", nameof(id));
        }

        await _codeStore.MarkConsumedAsync(id, consumedAt, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "AuthorizationCodeConsumed",
            TargetType = "AuthorizationCode",
            TargetId = id.ToString(),
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task StoreRefreshTokenAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.Id == Guid.Empty)
        {
            throw new ArgumentException("Token ID cannot be empty.", nameof(token));
        }
        ArgumentException.ThrowIfNullOrEmpty(token.TokenHash);

        return _refreshTokenStore.StoreAsync(token, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthRefreshToken?> FindRefreshTokenByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);
        return _refreshTokenStore.FindByHashAsync(tokenHash, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<CustomAuthPagedResult<CustomAuthRefreshToken>> GetRefreshTokensPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return _refreshTokenStore.GetPagedAsync(request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task MarkRefreshTokenConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Token ID cannot be empty.", nameof(id));
        }

        await _refreshTokenStore.MarkConsumedAsync(id, consumedAt, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "RefreshTokenConsumed",
            TargetType = "RefreshToken",
            TargetId = id.ToString(),
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task RevokeRefreshTokenAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Token ID cannot be empty.", nameof(id));
        }

        await _refreshTokenStore.RevokeAsync(id, revokedAt, cancellationToken).ConfigureAwait(false);

        await _auditLogStore.StoreAsync(new CustomAuthAuditLog
        {
            Id = Guid.NewGuid(),
            Action = "RefreshTokenRevoked",
            TargetType = "RefreshToken",
            TargetId = id.ToString(),
            Timestamp = _timeProvider.GetUtcNow()
        }, cancellationToken).ConfigureAwait(false);
    }
}
