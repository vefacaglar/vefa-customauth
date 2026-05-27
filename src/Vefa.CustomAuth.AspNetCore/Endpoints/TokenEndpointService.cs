using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class TokenEndpointService
{
    private readonly ICustomAuthClientStore _clientStore;
    private readonly ICustomAuthAuthorizationCodeStore _codeStore;
    private readonly ICustomAuthRefreshTokenStore _refreshTokenStore;
    private readonly ICustomAuthUserStore _userStore;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public TokenEndpointService(
        ICustomAuthClientStore clientStore,
        ICustomAuthAuthorizationCodeStore codeStore,
        ICustomAuthRefreshTokenStore refreshTokenStore,
        ICustomAuthUserStore userStore,
        ITokenIssuer tokenIssuer,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _clientStore = clientStore ?? throw new ArgumentNullException(nameof(clientStore));
        _codeStore = codeStore ?? throw new ArgumentNullException(nameof(codeStore));
        _refreshTokenStore = refreshTokenStore ?? throw new ArgumentNullException(nameof(refreshTokenStore));
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

        var client = await _clientStore.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized);
        }

        var code = await _codeStore.FindByHashAsync(TokenHasher.Hash(codeValue), cancellationToken).ConfigureAwait(false);
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

        var issued = await _tokenIssuer.IssueAsync(
            new TokenIssueRequest
            {
                Subject = user.UserId,
                ClientId = clientId,
                Scope = code.Scope,
                AuthTime = code.CreatedAt,
                AdditionalClaims = GetAdditionalClaims(user),
            },
            cancellationToken).ConfigureAwait(false);

        await StoreRefreshTokenAsync(issued.RefreshToken, client, user.UserId, code.Scope, null, now, cancellationToken).ConfigureAwait(false);
        await _codeStore.MarkConsumedAsync(code.Id, now, cancellationToken).ConfigureAwait(false);

        return Results.Json(CreateTokenResponse(issued, code.Scope, client.AllowRefreshTokens));
    }

    private async Task<IResult> ExchangeRefreshTokenAsync(IFormCollection form, CancellationToken cancellationToken)
    {
        var refreshTokenValue = form["refresh_token"].ToString();
        var clientId = form["client_id"].ToString();

        if (string.IsNullOrWhiteSpace(refreshTokenValue) || string.IsNullOrWhiteSpace(clientId))
        {
            return EndpointResults.OAuthError("invalid_request", "refresh_token and client_id are required.");
        }

        var client = await _clientStore.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized);
        }

        if (!client.AllowRefreshTokens)
        {
            return EndpointResults.OAuthError("unsupported_grant_type", "Refresh tokens are not enabled for this client.");
        }

        var refreshToken = await _refreshTokenStore.FindByHashAsync(TokenHasher.Hash(refreshTokenValue), cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        if (refreshToken is null
            || refreshToken.ConsumedAt is not null
            || refreshToken.RevokedAt is not null
            || refreshToken.ExpiresAt <= now
            || !string.Equals(refreshToken.ClientId, clientId, StringComparison.Ordinal))
        {
            return EndpointResults.OAuthError("invalid_grant", "The refresh token is invalid.");
        }

        var user = await _userStore.FindByIdAsync(refreshToken.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
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
            now,
            cancellationToken).ConfigureAwait(false);
        await _refreshTokenStore.MarkConsumedAsync(refreshToken.Id, now, cancellationToken).ConfigureAwait(false);

        return Results.Json(CreateTokenResponse(issued, refreshToken.Scope, includeRefreshToken: true));
    }

    private async Task StoreRefreshTokenAsync(
        string rawRefreshToken,
        CustomAuthClient client,
        string userId,
        string scope,
        Guid? sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!client.AllowRefreshTokens)
        {
            return;
        }

        await _refreshTokenStore.StoreAsync(
            new CustomAuthRefreshToken
            {
                Id = Guid.NewGuid(),
                TokenHash = TokenHasher.Hash(rawRefreshToken),
                ClientId = client.ClientId,
                UserId = userId,
                SessionId = sessionId,
                Scope = scope,
                CreatedAt = now,
                ExpiresAt = now.Add(GetRefreshTokenLifetime(client)),
            },
            cancellationToken).ConfigureAwait(false);
    }

    private TimeSpan GetRefreshTokenLifetime(CustomAuthClient client)
        => client.RefreshTokenLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds)
            : _options.CurrentValue.RefreshTokenLifetime;

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
