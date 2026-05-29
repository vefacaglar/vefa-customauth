using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints.Grants;

/// <summary>
/// Shared base for token-endpoint grant handlers. Holds the dependencies and helpers common to
/// the built-in grants (client lookup/authentication, scope checks, token-response shaping, and
/// refresh-token rotation/storage) so each handler implements only its own protocol logic.
/// </summary>
internal abstract class GrantHandlerBase : ICustomAuthGrantHandler
{
    protected static readonly IDictionary<string, string> BasicChallengeHeaders = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\"",
    };

    protected GrantHandlerBase(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ITokenIssuer tokenIssuer,
        ClientAuthenticationService clientAuthentication,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        ClientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        TokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        TokenIssuer = tokenIssuer ?? throw new ArgumentNullException(nameof(tokenIssuer));
        ClientAuthentication = clientAuthentication ?? throw new ArgumentNullException(nameof(clientAuthentication));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        TimeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    protected ICustomAuthClientManager ClientManager { get; }

    protected ICustomAuthTokenManager TokenManager { get; }

    protected ITokenIssuer TokenIssuer { get; }

    protected ClientAuthenticationService ClientAuthentication { get; }

    protected IOptionsMonitor<CustomAuthOptions> Options { get; }

    protected TimeProvider TimeProvider { get; }

    /// <inheritdoc />
    public abstract string GrantType { get; }

    /// <inheritdoc />
    public abstract Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default);

    protected static IResult UnknownClient()
        => EndpointResults.OAuthError(
            "invalid_client",
            "The client is not registered.",
            StatusCodes.Status401Unauthorized,
            BasicChallengeHeaders);

    protected static bool IsScopeAllowed(CustomAuthClient client, string scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return true;
        }

        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return requestedScopes.All(requested => client.AllowedScopes.Contains(requested, StringComparer.Ordinal));
    }

    protected static bool CanIssueRefreshToken(CustomAuthClient client, string scope)
        => client.AllowRefreshTokens && HasOfflineAccess(scope);

    protected static bool HasOfflineAccess(string scope)
        => scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains("offline_access", StringComparer.Ordinal);

    protected static object CreateTokenResponse(IssuedTokens issued, string scope, bool includeRefreshToken)
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

    protected async Task StoreRefreshTokenAsync(
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

        await TokenManager.StoreRefreshTokenAsync(
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

    protected DateTimeOffset GetRefreshTokenExpiresAt(CustomAuthClient client, DateTimeOffset now, DateTimeOffset absoluteExpiresAt)
    {
        var slidingExpiresAt = now.Add(GetRefreshTokenLifetime(client));
        return slidingExpiresAt <= absoluteExpiresAt ? slidingExpiresAt : absoluteExpiresAt;
    }

    protected TimeSpan GetRefreshTokenLifetime(CustomAuthClient client)
        => client.RefreshTokenLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds)
            : Options.CurrentValue.RefreshTokenLifetime;

    protected TimeSpan GetRefreshTokenAbsoluteLifetime(CustomAuthClient client)
    {
        var slidingLifetime = GetRefreshTokenLifetime(client);
        var configuredLifetime = client.RefreshTokenAbsoluteLifetimeSeconds > 0
            ? TimeSpan.FromSeconds(client.RefreshTokenAbsoluteLifetimeSeconds)
            : Options.CurrentValue.RefreshTokenAbsoluteLifetime;
        return configuredLifetime >= slidingLifetime ? configuredLifetime : slidingLifetime;
    }
}
