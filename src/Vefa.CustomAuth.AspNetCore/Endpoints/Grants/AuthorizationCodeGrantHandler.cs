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
/// Handles the <c>authorization_code</c> grant: validates the PKCE-protected code, authenticates
/// the client, and issues access, ID, and (when permitted) refresh tokens.
/// </summary>
internal sealed partial class AuthorizationCodeGrantHandler : GrantHandlerBase
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthProfileService _profileService;
    private readonly ILogger<AuthorizationCodeGrantHandler> _logger;

    public AuthorizationCodeGrantHandler(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ITokenIssuer tokenIssuer,
        ClientAuthenticationService clientAuthentication,
        ICustomAuthUserStore userStore,
        ICustomAuthProfileService profileService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<AuthorizationCodeGrantHandler> logger)
        : base(clientManager, tokenManager, tokenIssuer, clientAuthentication, options, timeProvider)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _profileService = profileService ?? throw new ArgumentNullException(nameof(profileService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public override string GrantType => "authorization_code";

    public override async Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default)
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

        var client = await ClientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId, "authorization_code");
            return UnknownClient();
        }

        var authError = await ClientAuthentication.AuthenticateAsync(client, form, cancellationToken).ConfigureAwait(false);
        if (authError is not null)
        {
            return authError;
        }

        var code = await TokenManager.FindAuthorizationCodeByHashAsync(TokenHasher.Hash(codeValue), cancellationToken).ConfigureAwait(false);
        var now = TimeProvider.GetUtcNow();

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

        var consumed = await TokenManager.MarkAuthorizationCodeConsumedAsync(code.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            LogCodeConcurrentConsume(clientId, code.Id);
            return InvalidAuthorizationCode();
        }

        var profileContext = new CustomAuthProfileContext(user.UserId, client, code.Scope);
        await _profileService.GetProfileDataAsync(profileContext, cancellationToken).ConfigureAwait(false);

        var issued = await TokenIssuer.IssueAsync(
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

    private static IResult InvalidAuthorizationCode()
        => EndpointResults.OAuthError("invalid_grant", "The authorization code is invalid.");

    // Token endpoint diagnostics. Event IDs 2001-2020. Raw codes, verifiers, and tokens are never
    // logged (only the stored entity's Guid Id and non-secret request metadata such as client_id,
    // redirect_uri, and scope).

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning,
        Message = "Token request rejected (invalid_client): client '{ClientId}' is not registered (grant_type: {GrantType}).")]
    private partial void LogUnknownClient(string clientId, string grantType);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Warning,
        Message = "User '{GrantType}' grant rejected (invalid_grant): the user is no longer active (client: {ClientId}).")]
    private partial void LogUserInactive(string clientId, string grantType);

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
}
