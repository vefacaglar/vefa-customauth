using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class TokenEndpointService
{
    private readonly ICustomAuthClientManager _clientManager;
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly ICustomAuthUserStore _userStore;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public TokenEndpointService(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ICustomAuthUserStore userStore,
        ITokenIssuer tokenIssuer,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _tokenIssuer = tokenIssuer ?? throw new ArgumentNullException(nameof(tokenIssuer));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<IResult> HandleAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.HasFormContentType)
        {
            return EndpointResults.OAuthError("invalid_request", "Token requests must use application/x-www-form-urlencoded.");
        }

        var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        return form["grant_type"].ToString() switch
        {
            "authorization_code" => await ExchangeAuthorizationCodeAsync(form, cancellationToken).ConfigureAwait(false),
            "refresh_token" => await ExchangeRefreshTokenAsync(form, cancellationToken).ConfigureAwait(false),
            _ => EndpointResults.OAuthError("unsupported_grant_type", "Only authorization_code and refresh_token grants are supported."),
        };
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
            return EndpointResults.OAuthError("invalid_request", "code, redirect_uri, client_id, and code_verifier are required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\""
            };
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized, headers);
        }

        var code = await _tokenManager.FindAuthorizationCodeByHashAsync(TokenHasher.Hash(codeValue), cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        if (code is null
            || code.ConsumedAt is not null
            || code.ExpiresAt <= now
            || !string.Equals(code.ClientId, clientId, StringComparison.Ordinal)
            || !string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(code.CodeChallenge)
            || string.IsNullOrWhiteSpace(code.CodeChallengeMethod)
            || !PkceVerifier.Verify(verifier, code.CodeChallenge, code.CodeChallengeMethod))
        {
            return EndpointResults.OAuthError("invalid_grant", "The authorization code is invalid.");
        }

        var user = await _userStore.FindByIdAsync(code.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return EndpointResults.OAuthError("invalid_grant", "The authorization code is invalid.");
        }

        var consumed = await _tokenManager.MarkAuthorizationCodeConsumedAsync(code.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            return EndpointResults.OAuthError("invalid_grant", "The authorization code is invalid.");
        }

        var issued = await _tokenIssuer.IssueAsync(
            new TokenIssueRequest
            {
                Subject = user.UserId,
                ClientId = clientId,
                Scope = code.Scope,
                AuthTime = code.CreatedAt,
                Nonce = code.Nonce,
                AdditionalClaims = GetAdditionalClaims(user),
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

        return EndpointResults.NoStoreJson(CreateTokenResponse(issued, code.Scope, includeRefreshToken));
    }

    private async Task<IResult> ExchangeRefreshTokenAsync(IFormCollection form, CancellationToken cancellationToken)
    {
        var refreshTokenValue = form["refresh_token"].ToString();
        var clientId = form["client_id"].ToString();

        if (string.IsNullOrWhiteSpace(refreshTokenValue) || string.IsNullOrWhiteSpace(clientId))
        {
            return EndpointResults.OAuthError("invalid_request", "refresh_token and client_id are required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            var headers = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\""
            };
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized, headers);
        }

        if (!client.AllowRefreshTokens)
        {
            return EndpointResults.OAuthError("unsupported_grant_type", "Refresh tokens are not enabled for this client.");
        }

        var refreshToken = await _tokenManager.FindRefreshTokenByHashAsync(TokenHasher.Hash(refreshTokenValue), cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        if (refreshToken is null
            || refreshToken.ExpiresAt <= now
            || refreshToken.AbsoluteExpiresAt <= now
            || refreshToken.RevokedAt is not null
            || !string.Equals(refreshToken.ClientId, clientId, StringComparison.Ordinal))
        {
            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        if (!HasOfflineAccess(refreshToken.Scope))
        {
            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        if (refreshToken.ConsumedAt is not null)
        {
            if (_options.CurrentValue.DetectRefreshTokenReuse)
            {
                await _tokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
            }

            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        var user = await _userStore.FindByIdAsync(refreshToken.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        var consumed = await _tokenManager.MarkRefreshTokenConsumedAsync(refreshToken.Id, now, cancellationToken).ConfigureAwait(false);
        if (!consumed)
        {
            // Lost the atomic check-and-set. Another caller already consumed this token between our
            // lookup and our update — treat it as reuse and revoke the chain.
            if (_options.CurrentValue.DetectRefreshTokenReuse)
            {
                await _tokenManager.HandleRefreshTokenReuseAsync(refreshToken, now, cancellationToken).ConfigureAwait(false);
            }

            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        var issued = await _tokenIssuer.IssueAsync(
            new TokenIssueRequest
            {
                Subject = user.UserId,
                ClientId = clientId,
                Scope = refreshToken.Scope,
                AdditionalClaims = GetAdditionalClaims(user),
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

        return EndpointResults.NoStoreJson(CreateTokenResponse(issued, refreshToken.Scope, includeRefreshToken: true));
    }

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

    private static IReadOnlyDictionary<string, string>? GetAdditionalClaims(CustomAuthUserInfo user)
    {
        var claims = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(user.UserName))
        {
            claims["name"] = user.UserName;
        }

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            claims["email"] = user.Email;
        }

        if (user.AdditionalClaims is not null)
        {
            foreach (var claim in user.AdditionalClaims)
            {
                claims.TryAdd(claim.Key, claim.Value);
            }
        }

        return claims.Count == 0 ? null : claims;
    }

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
}
