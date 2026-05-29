using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints.Grants;

/// <summary>
/// Handles the <c>refresh_token</c> grant: validates and rotates the session-bound refresh token,
/// detects reuse, and issues a fresh access/ID token pair plus a rotated refresh token.
/// </summary>
internal sealed partial class RefreshTokenGrantHandler : GrantHandlerBase
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthProfileService _profileService;
    private readonly ILogger<RefreshTokenGrantHandler> _logger;

    public RefreshTokenGrantHandler(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ITokenIssuer tokenIssuer,
        ClientAuthenticationService clientAuthentication,
        ICustomAuthUserStore userStore,
        ICustomAuthProfileService profileService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<RefreshTokenGrantHandler> logger)
        : base(clientManager, tokenManager, tokenIssuer, clientAuthentication, options, timeProvider)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _profileService = profileService ?? throw new ArgumentNullException(nameof(profileService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public override string GrantType => "refresh_token";

    public override async Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default)
    {
        var refreshTokenValue = form["refresh_token"].ToString();
        var clientId = form["client_id"].ToString();

        if (string.IsNullOrWhiteSpace(refreshTokenValue) || string.IsNullOrWhiteSpace(clientId))
        {
            var missing = string.Join(", ", new[]
            {
                string.IsNullOrWhiteSpace(refreshTokenValue) ? "refresh_token" : null,
                string.IsNullOrWhiteSpace(clientId) ? "client_id" : null,
            }.Where(p => p is not null));
            LogRefreshExchangeMissingParameters(missing);
            return EndpointResults.OAuthError("invalid_request", "refresh_token and client_id are required.");
        }

        var client = await ClientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId, "refresh_token");
            return UnknownClient();
        }

        var authError = await ClientAuthentication.AuthenticateAsync(client, form, cancellationToken).ConfigureAwait(false);
        if (authError is not null)
        {
            return authError;
        }

        if (!client.AllowRefreshTokens)
        {
            LogRefreshTokensNotEnabled(clientId);
            return EndpointResults.OAuthError("unsupported_grant_type", "Refresh tokens are not enabled for this client.");
        }

        var refreshToken = await TokenManager.FindRefreshTokenByHashAsync(TokenHasher.Hash(refreshTokenValue), cancellationToken).ConfigureAwait(false);
        var now = TimeProvider.GetUtcNow();

        // As with authorization codes, the client always receives the same opaque invalid_grant;
        // the precise reason is logged server-side only.
        if (refreshToken is null)
        {
            LogRefreshTokenNotFound(clientId);
            return InvalidRefreshToken();
        }

        if (refreshToken.ExpiresAt <= now)
        {
            LogRefreshTokenExpired(clientId, refreshToken.Id, "sliding", refreshToken.ExpiresAt);
            return InvalidRefreshToken();
        }

        if (refreshToken.AbsoluteExpiresAt <= now)
        {
            LogRefreshTokenExpired(clientId, refreshToken.Id, "absolute", refreshToken.AbsoluteExpiresAt);
            return InvalidRefreshToken();
        }

        if (refreshToken.RevokedAt is not null)
        {
            LogRefreshTokenRevoked(clientId, refreshToken.Id, refreshToken.RevokedAt.Value);
            return InvalidRefreshToken();
        }

        if (!string.Equals(refreshToken.ClientId, clientId, StringComparison.Ordinal))
        {
            LogRefreshTokenClientMismatch(refreshToken.ClientId, clientId, refreshToken.Id);
            return InvalidRefreshToken();
        }

        if (!HasOfflineAccess(refreshToken.Scope))
        {
            LogRefreshTokenMissingOfflineAccess(clientId, refreshToken.Id, refreshToken.Scope);
            return InvalidRefreshToken();
        }

        if (refreshToken.ConsumedAt is not null)
        {
            LogRefreshTokenReuse(clientId, refreshToken.Id, Options.CurrentValue.DetectRefreshTokenReuse);
            if (Options.CurrentValue.DetectRefreshTokenReuse)
            {
                await TokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
            }

            return InvalidRefreshToken();
        }

        var user = await _userStore.FindByIdAsync(refreshToken.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            LogRefreshTokenUserNotFound(clientId, refreshToken.Id);
            return InvalidRefreshToken();
        }

        var isActive = await _profileService.IsUserActiveAsync(user.UserId, cancellationToken).ConfigureAwait(false);
        if (!isActive)
        {
            LogUserInactive(clientId, "refresh_token");
            return EndpointResults.OAuthError("invalid_grant", "The user is no longer active.");
        }

        var consumed = await TokenManager.MarkRefreshTokenConsumedAsync(refreshToken.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            // Lost the atomic check-and-set. Another caller already consumed this token between our
            // lookup and our update — treat it as reuse and revoke the chain.
            LogRefreshTokenConcurrentConsume(clientId, refreshToken.Id, Options.CurrentValue.DetectRefreshTokenReuse);
            if (Options.CurrentValue.DetectRefreshTokenReuse)
            {
                await TokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
            }

            return InvalidRefreshToken();
        }

        var profileContext = new CustomAuthProfileContext(user.UserId, client, refreshToken.Scope);
        await _profileService.GetProfileDataAsync(profileContext, cancellationToken).ConfigureAwait(false);

        var issued = await TokenIssuer.IssueAsync(
            new TokenIssueRequest
            {
                Subject = user.UserId,
                ClientId = clientId,
                Scope = refreshToken.Scope,
                AdditionalClaims = profileContext.Claims.Count > 0 ? profileContext.Claims : null,
            },
            cancellationToken).ConfigureAwait(false);

        await StoreRefreshTokenAsync(
            issued.RefreshToken,
            client,
            user.UserId,
            refreshToken.Scope,
            refreshToken.SessionId,
            refreshToken.Id,
            refreshToken.AbsoluteExpiresAt,
            now,
            cancellationToken).ConfigureAwait(false);

        LogRefreshExchangeSucceeded(clientId, refreshToken.Scope);
        return EndpointResults.NoStoreJson(CreateTokenResponse(issued, refreshToken.Scope, includeRefreshToken: true));
    }

    private static IResult InvalidRefreshToken()
        => EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");

    // Token endpoint diagnostics. Event IDs 2001/2002 (shared) and 2030-2040. Raw tokens are never
    // logged (only the stored entity's Guid Id and non-secret request metadata).

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning,
        Message = "Token request rejected (invalid_client): client '{ClientId}' is not registered (grant_type: {GrantType}).")]
    private partial void LogUnknownClient(string clientId, string grantType);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning,
        Message = "User '{GrantType}' grant rejected (invalid_grant): the user is no longer active (client: {ClientId}).")]
    private partial void LogUserInactive(string clientId, string grantType);

    [LoggerMessage(EventId = 2030, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_request): missing required parameter(s): {MissingParameters}.")]
    private partial void LogRefreshExchangeMissingParameters(string missingParameters);

    [LoggerMessage(EventId = 2031, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (unsupported_grant_type): refresh tokens are not enabled for client '{ClientId}'.")]
    private partial void LogRefreshTokensNotEnabled(string clientId);

    [LoggerMessage(EventId = 2032, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): no matching refresh token was found. It may have been rotated, revoked and purged, or never issued (client: {ClientId}).")]
    private partial void LogRefreshTokenNotFound(string clientId);

    [LoggerMessage(EventId = 2033, Level = LogLevel.Information,
        Message = "Refresh token exchange rejected (invalid_grant): the {ExpiryKind} expiry elapsed at {ExpiresAt:o} (client: {ClientId}, tokenId: {TokenId}).")]
    private partial void LogRefreshTokenExpired(string clientId, Guid tokenId, string expiryKind, DateTimeOffset expiresAt);

    [LoggerMessage(EventId = 2034, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): the token was revoked at {RevokedAt:o} (client: {ClientId}, tokenId: {TokenId}).")]
    private partial void LogRefreshTokenRevoked(string clientId, Guid tokenId, DateTimeOffset revokedAt);

    [LoggerMessage(EventId = 2035, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): the token was issued to client '{TokenClientId}' but presented by client '{RequestClientId}' (tokenId: {TokenId}).")]
    private partial void LogRefreshTokenClientMismatch(string tokenClientId, string requestClientId, Guid tokenId);

    [LoggerMessage(EventId = 2036, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): the token's scope '{Scope}' does not include offline_access (client: {ClientId}, tokenId: {TokenId}).")]
    private partial void LogRefreshTokenMissingOfflineAccess(string clientId, Guid tokenId, string scope);

    [LoggerMessage(EventId = 2037, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): the token was already consumed, indicating possible reuse (client: {ClientId}, tokenId: {TokenId}, reuseDetectionEnabled: {ReuseDetectionEnabled}).")]
    private partial void LogRefreshTokenReuse(string clientId, Guid tokenId, bool reuseDetectionEnabled);

    [LoggerMessage(EventId = 2038, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): the subject user could not be found (client: {ClientId}, tokenId: {TokenId}).")]
    private partial void LogRefreshTokenUserNotFound(string clientId, Guid tokenId);

    [LoggerMessage(EventId = 2039, Level = LogLevel.Warning,
        Message = "Refresh token exchange rejected (invalid_grant): another concurrent request consumed the token first, indicating possible reuse (client: {ClientId}, tokenId: {TokenId}, reuseDetectionEnabled: {ReuseDetectionEnabled}).")]
    private partial void LogRefreshTokenConcurrentConsume(string clientId, Guid tokenId, bool reuseDetectionEnabled);

    [LoggerMessage(EventId = 2040, Level = LogLevel.Information,
        Message = "Refresh token exchange succeeded (client: {ClientId}, scope: '{Scope}').")]
    private partial void LogRefreshExchangeSucceeded(string clientId, string scope);
}
