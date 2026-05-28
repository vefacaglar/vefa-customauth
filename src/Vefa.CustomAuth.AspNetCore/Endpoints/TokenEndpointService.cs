using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed partial class TokenEndpointService
{
    private readonly ICustomAuthClientManager _clientManager;
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly ICustomAuthUserStore _userStore;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly ICustomAuthProfileService _profileService;
    private readonly ClientAuthenticationService _clientAuthentication;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TokenEndpointService> _logger;

    public TokenEndpointService(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ICustomAuthUserStore userStore,
        ITokenIssuer tokenIssuer,
        ICustomAuthProfileService profileService,
        ClientAuthenticationService clientAuthentication,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<TokenEndpointService> logger)
    {
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _tokenIssuer = tokenIssuer ?? throw new ArgumentNullException(nameof(tokenIssuer));
        _profileService = profileService ?? throw new ArgumentNullException(nameof(profileService));
        _clientAuthentication = clientAuthentication ?? throw new ArgumentNullException(nameof(clientAuthentication));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<IResult> HandleAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.HasFormContentType)
        {
            return EndpointResults.OAuthError("invalid_request", "Token requests must use application/x-www-form-urlencoded.");
        }

        var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var grantType = form["grant_type"].ToString();
        switch (grantType)
        {
            case "authorization_code":
                return await ExchangeAuthorizationCodeAsync(form, cancellationToken).ConfigureAwait(false);
            case "refresh_token":
                return await ExchangeRefreshTokenAsync(form, cancellationToken).ConfigureAwait(false);
            default:
                LogUnsupportedGrantType(string.IsNullOrEmpty(grantType) ? "(none)" : grantType);
                return EndpointResults.OAuthError("unsupported_grant_type", "Only authorization_code and refresh_token grants are supported.");
        }
    }

    private async Task<IResult> ExchangeAuthorizationCodeAsync(IFormCollection form, CancellationToken cancellationToken)
    {
        var codeValue = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var clientId = form["client_id"].ToString();
        var verifier = form["code_verifier"].ToString();

        if (string.IsNullOrWhiteSpace(codeValue)
            || string.IsNullOrWhiteSpace(redirectUri)
            || string.IsNullOrWhiteSpace(clientId)
            || string.IsNullOrWhiteSpace(verifier))
        {
            var missing = string.Join(", ", new[]
            {
                string.IsNullOrWhiteSpace(codeValue) ? "code" : null,
                string.IsNullOrWhiteSpace(redirectUri) ? "redirect_uri" : null,
                string.IsNullOrWhiteSpace(clientId) ? "client_id" : null,
                string.IsNullOrWhiteSpace(verifier) ? "code_verifier" : null,
            }.Where(p => p is not null));
            LogCodeExchangeMissingParameters(missing);
            return EndpointResults.OAuthError("invalid_request", "code, redirect_uri, client_id, and code_verifier are required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId, "authorization_code");
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\""
            };
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized, headers);
        }

        var authError = await _clientAuthentication.AuthenticateAsync(client, form, cancellationToken).ConfigureAwait(false);
        if (authError is not null)
        {
            return authError;
        }

        var code = await _tokenManager.FindAuthorizationCodeByHashAsync(TokenHasher.Hash(codeValue), cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();

        // Each branch returns the same opaque invalid_grant to the client (per RFC 6749, the reason
        // must not leak), but logs the precise cause server-side for diagnostics.
        if (code is null)
        {
            LogCodeNotFound(clientId);
            return InvalidAuthorizationCode();
        }

        if (code.ConsumedAt is not null)
        {
            LogCodeAlreadyConsumed(clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        if (code.ExpiresAt <= now)
        {
            LogCodeExpired(clientId, code.Id, code.ExpiresAt);
            return InvalidAuthorizationCode();
        }

        if (!string.Equals(code.ClientId, clientId, StringComparison.Ordinal))
        {
            LogCodeClientMismatch(code.ClientId, clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        if (!string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            LogCodeRedirectUriMismatch(code.RedirectUri, redirectUri, clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        if (string.IsNullOrWhiteSpace(code.CodeChallenge) || string.IsNullOrWhiteSpace(code.CodeChallengeMethod))
        {
            LogCodeMissingPkceChallenge(clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        if (!PkceVerifier.Verify(verifier, code.CodeChallenge, code.CodeChallengeMethod))
        {
            LogPkceVerificationFailed(clientId, code.Id, code.CodeChallengeMethod);
            return InvalidAuthorizationCode();
        }

        var user = await _userStore.FindByIdAsync(code.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            LogCodeUserNotFound(clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        var isActive = await _profileService.IsUserActiveAsync(user.UserId, cancellationToken).ConfigureAwait(false);
        if (!isActive)
        {
            LogUserInactive(clientId, "authorization_code");
            return EndpointResults.OAuthError("invalid_grant", "The user is no longer active.");
        }

        var consumed = await _tokenManager.MarkAuthorizationCodeConsumedAsync(code.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            LogCodeConcurrentConsume(clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        var profileContext = new CustomAuthProfileContext(user.UserId, client, code.Scope);
        await _profileService.GetProfileDataAsync(profileContext, cancellationToken).ConfigureAwait(false);

        var issued = await _tokenIssuer.IssueAsync(
            new TokenIssueRequest
            {
                Subject = user.UserId,
                ClientId = clientId,
                Scope = code.Scope,
                AuthTime = code.CreatedAt,
                Nonce = code.Nonce,
                AdditionalClaims = profileContext.Claims.Count > 0 ? profileContext.Claims : null,
            },
            cancellationToken).ConfigureAwait(false);

        var absoluteExpiresAt = now.Add(GetRefreshTokenAbsoluteLifetime(client));
        var includeRefreshToken = CanIssueRefreshToken(client, code.Scope);
        await StoreRefreshTokenAsync(
            issued.RefreshToken,
            client,
            user.UserId,
            code.Scope,
            code.SessionId,
            parentTokenId: null,
            absoluteExpiresAt,
            now,
            cancellationToken).ConfigureAwait(false);

        LogCodeExchangeSucceeded(clientId, code.Scope, includeRefreshToken);
        return EndpointResults.NoStoreJson(CreateTokenResponse(issued, code.Scope, includeRefreshToken));
    }

    private async Task<IResult> ExchangeRefreshTokenAsync(IFormCollection form, CancellationToken cancellationToken)
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

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId, "refresh_token");
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\""
            };
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized, headers);
        }

        var authError = await _clientAuthentication.AuthenticateAsync(client, form, cancellationToken).ConfigureAwait(false);
        if (authError is not null)
        {
            return authError;
        }

        if (!client.AllowRefreshTokens)
        {
            LogRefreshTokensNotEnabled(clientId);
            return EndpointResults.OAuthError("unsupported_grant_type", "Refresh tokens are not enabled for this client.");
        }

        var refreshToken = await _tokenManager.FindRefreshTokenByHashAsync(TokenHasher.Hash(refreshTokenValue), cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();

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
            LogRefreshTokenReuse(clientId, refreshToken.Id, _options.CurrentValue.DetectRefreshTokenReuse);
            if (_options.CurrentValue.DetectRefreshTokenReuse)
            {
                await _tokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
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

        var consumed = await _tokenManager.MarkRefreshTokenConsumedAsync(refreshToken.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            // Lost the atomic check-and-set. Another caller already consumed this token between our
            // lookup and our update — treat it as reuse and revoke the chain.
            LogRefreshTokenConcurrentConsume(clientId, refreshToken.Id, _options.CurrentValue.DetectRefreshTokenReuse);
            if (_options.CurrentValue.DetectRefreshTokenReuse)
            {
                await _tokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
            }

            return InvalidRefreshToken();
        }

        var profileContext = new CustomAuthProfileContext(user.UserId, client, refreshToken.Scope);
        await _profileService.GetProfileDataAsync(profileContext, cancellationToken).ConfigureAwait(false);

        var issued = await _tokenIssuer.IssueAsync(
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

    private static IResult InvalidAuthorizationCode()
        => EndpointResults.OAuthError("invalid_grant", "The authorization code is invalid.");

    private static IResult InvalidRefreshToken()
        => EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");

    private async Task StoreRefreshTokenAsync(
        string rawRefreshToken,
        CustomAuthClient client,
        string userId,
        string scope,
        Guid? sessionId,
        Guid? parentTokenId,
        DateTimeOffset absoluteExpiresAt,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!CanIssueRefreshToken(client, scope))
        {
            return;
        }

        await _tokenManager.StoreRefreshTokenAsync(
            new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = TokenHasher.Hash(rawRefreshToken),
                ClientId = client.ClientId,
                UserId = userId,
                SessionId = sessionId,
                ParentTokenId = parentTokenId,
                Scope = scope,
                CreatedAt = now,
                ExpiresAt = GetRefreshTokenExpiresAt(client, now, absoluteExpiresAt),
                AbsoluteExpiresAt = absoluteExpiresAt,
            },
            cancellationToken).ConfigureAwait(false);
    }

    private DateTimeOffset GetRefreshTokenExpiresAt(CustomAuthClient client, DateTimeOffset now, DateTimeOffset absoluteExpiresAt)
    {
        var slidingExpiresAt = now.Add(GetRefreshTokenLifetime(client));
        return slidingExpiresAt <= absoluteExpiresAt ? slidingExpiresAt : absoluteExpiresAt;
    }

    private TimeSpan GetRefreshTokenLifetime(CustomAuthClient client)
        => client.RefreshTokenLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds)
            : _options.CurrentValue.RefreshTokenLifetime;

    private TimeSpan GetRefreshTokenAbsoluteLifetime(CustomAuthClient client)
    {
        var slidingLifetime = GetRefreshTokenLifetime(client);
        var configuredLifetime = client.RefreshTokenAbsoluteLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(client.RefreshTokenAbsoluteLifetimeSeconds)
            : _options.CurrentValue.RefreshTokenAbsoluteLifetime;
        return configuredLifetime >= slidingLifetime ? configuredLifetime : slidingLifetime;
    }

    private static bool CanIssueRefreshToken(CustomAuthClient client, string scope)
        => client.AllowRefreshTokens && HasOfflineAccess(scope);

    private static bool HasOfflineAccess(string scope)
        => scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains("offline_access", StringComparer.Ordinal);

    private static object CreateTokenResponse(IssuedTokens issued, string scope, bool includeRefreshToken)
    {
        var response = new Dictionary<string, object?>
        {
            ["access_token"] = issued.AccessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = issued.AccessTokenExpiresInSeconds,
            ["id_token"] = issued.IdToken,
            ["scope"] = scope,
        };

        if (includeRefreshToken)
        {
            response["refresh_token"] = issued.RefreshToken;
        }

        return response;
    }

    // Token endpoint diagnostics. Event IDs 2000-2099. Raw codes, verifiers, and tokens are never
    // logged (only the stored entity's Guid Id and non-secret request metadata such as client_id,
    // redirect_uri, and scope).

    [LoggerMessage(EventId = 2000, Level = LogLevel.Warning,
        Message = "Token request rejected: unsupported grant_type '{GrantType}'.")]
    private partial void LogUnsupportedGrantType(string grantType);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning,
        Message = "Token request rejected (invalid_client): client '{ClientId}' is not registered (grant_type: {GrantType}).")]
    private partial void LogUnknownClient(string clientId, string grantType);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning,
        Message = "User '{GrantType}' grant rejected (invalid_grant): the user is no longer active (client: {ClientId}).")]
    private partial void LogUserInactive(string clientId, string grantType);

    // --- authorization_code path ---

    [LoggerMessage(EventId = 2010, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_request): missing required parameter(s): {MissingParameters}.")]
    private partial void LogCodeExchangeMissingParameters(string missingParameters);

    [LoggerMessage(EventId = 2011, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): no matching code was found. The code may already have been redeemed, expired and purged, or never issued (client: {ClientId}).")]
    private partial void LogCodeNotFound(string clientId);

    [LoggerMessage(EventId = 2012, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): the code was already consumed (client: {ClientId}, codeId: {CodeId}).")]
    private partial void LogCodeAlreadyConsumed(string clientId, Guid codeId);

    [LoggerMessage(EventId = 2013, Level = LogLevel.Information,
        Message = "Authorization code exchange rejected (invalid_grant): the code expired at {ExpiresAt:o} (client: {ClientId}, codeId: {CodeId}).")]
    private partial void LogCodeExpired(string clientId, Guid codeId, DateTimeOffset expiresAt);

    [LoggerMessage(EventId = 2014, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): the code was issued to client '{CodeClientId}' but presented by client '{RequestClientId}' (codeId: {CodeId}).")]
    private partial void LogCodeClientMismatch(string codeClientId, string requestClientId, Guid codeId);

    [LoggerMessage(EventId = 2015, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): redirect_uri does not match. The code was bound to '{BoundRedirectUri}' but the token request supplied '{RequestRedirectUri}' (client: {ClientId}, codeId: {CodeId}). The token request redirect_uri must be byte-for-byte identical to the one used at /authorize.")]
    private partial void LogCodeRedirectUriMismatch(string boundRedirectUri, string requestRedirectUri, string clientId, Guid codeId);

    [LoggerMessage(EventId = 2016, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): the stored code has no PKCE challenge, so it cannot be verified (client: {ClientId}, codeId: {CodeId}).")]
    private partial void LogCodeMissingPkceChallenge(string clientId, Guid codeId);

    [LoggerMessage(EventId = 2017, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): PKCE verification failed. The supplied code_verifier does not match the code_challenge sent to /authorize (client: {ClientId}, codeId: {CodeId}, method: {Method}).")]
    private partial void LogPkceVerificationFailed(string clientId, Guid codeId, string method);

    [LoggerMessage(EventId = 2018, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): the subject user could not be found (client: {ClientId}, codeId: {CodeId}).")]
    private partial void LogCodeUserNotFound(string clientId, Guid codeId);

    [LoggerMessage(EventId = 2019, Level = LogLevel.Warning,
        Message = "Authorization code exchange rejected (invalid_grant): another concurrent request consumed the code first (client: {ClientId}, codeId: {CodeId}).")]
    private partial void LogCodeConcurrentConsume(string clientId, Guid codeId);

    [LoggerMessage(EventId = 2020, Level = LogLevel.Information,
        Message = "Authorization code exchange succeeded (client: {ClientId}, scope: '{Scope}', refreshTokenIssued: {RefreshTokenIssued}).")]
    private partial void LogCodeExchangeSucceeded(string clientId, string scope, bool refreshTokenIssued);

    // --- refresh_token path ---

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
