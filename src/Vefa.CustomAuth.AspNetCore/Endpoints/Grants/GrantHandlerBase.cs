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
        Services.TokenAudienceResolver audienceResolver,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        ClientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        TokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        TokenIssuer = tokenIssuer ?? throw new ArgumentNullException(nameof(tokenIssuer));
        ClientAuthentication = clientAuthentication ?? throw new ArgumentNullException(nameof(clientAuthentication));
        AudienceResolver = audienceResolver ?? throw new ArgumentNullException(nameof(audienceResolver));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        TimeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    protected ICustomAuthClientManager ClientManager { get; }

    protected ICustomAuthTokenManager TokenManager { get; }

    protected ITokenIssuer TokenIssuer { get; }

    protected ClientAuthenticationService ClientAuthentication { get; }

    protected Services.TokenAudienceResolver AudienceResolver { get; }

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

    protected static IResult InvalidTarget()
        => EndpointResults.OAuthError("invalid_target", "The requested resource is invalid, unknown, or not permitted for this grant.");

    /// <summary>
    /// Extracts the distinct RFC 8707 <c>resource</c> values from the token request form.
    /// </summary>
    protected static string[] ParseRequestedResources(IFormCollection form)
        => form["resource"]
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => r!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    /// <summary>
    /// Applies RFC 8707 narrowing: with no requested resources the grant's full audience set is
    /// used; otherwise every requested resource must be within the allowed set and the audiences
    /// narrow to exactly the requested resources. Returns false (with the first offending value
    /// in <paramref name="rejectedResource"/>) when a requested resource is not allowed.
    /// </summary>
    protected static bool TryResolveGrantAudiences(
        string[] requestedResources,
        IReadOnlyList<string> allowedAudiences,
        out IReadOnlyList<string> audiences,
        out string? rejectedResource)
    {
        if (requestedResources.Length == 0)
        {
            audiences = allowedAudiences;
            rejectedResource = null;
            return true;
        }

        rejectedResource = requestedResources.FirstOrDefault(r => !allowedAudiences.Contains(r, StringComparer.Ordinal));
        if (rejectedResource is not null)
        {
            audiences = Array.Empty<string>();
            return false;
        }

        audiences = requestedResources;
        return true;
    }

    /// <summary>
    /// Returns the allowed audience set of a grant: the resources bound to the grant when it has
    /// any, otherwise the audiences mapped by its granted scopes.
    /// </summary>
    protected async Task<IReadOnlyList<string>> GetAllowedAudiencesAsync(string? grantResources, string scope, CancellationToken cancellationToken)
    {
        IReadOnlyList<string> boundResources = Services.TokenAudienceResolver.SplitResources(grantResources);
        return boundResources.Count > 0
            ? boundResources
            : await AudienceResolver.ResolveAudiencesAsync(scope, cancellationToken).ConfigureAwait(false);
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
        string? resources,
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
                Resources = resources,
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
