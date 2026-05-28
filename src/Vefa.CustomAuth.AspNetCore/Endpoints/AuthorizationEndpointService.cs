using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class AuthorizationEndpointService
{
    private readonly ICustomAuthClientManager _clientManager;
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public AuthorizationEndpointService(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        SessionCookieService sessionCookieService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;
        var clientId = request.Query["client_id"].ToString();
        var redirectUri = request.Query["redirect_uri"].ToString();
        var responseType = request.Query["response_type"].ToString();
        var scope = request.Query["scope"].ToString();
        var state = request.Query["state"].ToString();
        var codeChallenge = request.Query["code_challenge"].ToString();
        var codeChallengeMethod = request.Query["code_challenge_method"].ToString();
        var nonce = request.Query["nonce"].ToString();

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return EndpointResults.OAuthError("invalid_request", "client_id is required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            return EndpointResults.OAuthError("unauthorized_client", "The client is not registered.");
        }

        if (string.IsNullOrWhiteSpace(redirectUri) || !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return EndpointResults.OAuthError("invalid_request", "redirect_uri must exactly match a registered redirect URI.");
        }

        var validationError = ValidatePostRedirectUri(client, redirectUri, responseType, scope, codeChallenge, codeChallengeMethod, state);
        if (validationError is not null)
        {
            return validationError;
        }

        var prompt = request.Query["prompt"].ToString();
        var maxAgeStr = request.Query["max_age"].ToString();

        var prompts = (prompt ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);

        if (prompts.Contains("none") && prompts.Count > 1)
        {
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_request",
                "prompt=none cannot be combined with other prompt values.",
                state);
        }

        var session = await _sessionCookieService.GetCurrentSessionAsync(context, cancellationToken).ConfigureAwait(false);

        // Enforce max_age re-authentication
        if (session is not null && int.TryParse(maxAgeStr, out var maxAge) && maxAge > 0)
        {
            var nowUtc = _timeProvider.GetUtcNow();
            if (session.CreatedAt.AddSeconds(maxAge) < nowUtc)
            {
                session = null; // Force re-authentication by ignoring current session
            }
        }

        // Enforce prompt=login re-authentication
        if (prompts.Contains("login"))
        {
            session = null; // Always ignore session to force login screen
        }

        if (session is null)
        {
            if (prompts.Contains("none"))
            {
                return EndpointResults.OAuthAuthorizeRedirectError(
                    redirectUri,
                    "login_required",
                    "The user is not authenticated and prompt=none was requested.",
                    state);
            }

            return Results.Redirect(GetLoginUrl(context));
        }

        var rawCode = TokenHasher.CreateOpaqueToken();
        var now = _timeProvider.GetUtcNow();
        await _tokenManager.StoreAuthorizationCodeAsync(
            new CustomAuthAuthorizationCode
            {
                Id = Guid.NewGuid(),
                CodeHash = TokenHasher.Hash(rawCode),
                ClientId = client.ClientId,
                UserId = session.UserId,
                SessionId = session.Id,
                RedirectUri = redirectUri,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Scope = scope,
                Nonce = string.IsNullOrEmpty(nonce) ? null : nonce,
                CreatedAt = now,
                ExpiresAt = now.Add(_options.CurrentValue.AuthorizationCodeLifetime),
            },
            cancellationToken).ConfigureAwait(false);

        var redirectValues = new Dictionary<string, string?>
        {
            ["code"] = rawCode,
        };

        if (!string.IsNullOrEmpty(state))
        {
            redirectValues["state"] = state;
        }

        return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, redirectValues));
    }

    private IResult? ValidatePostRedirectUri(
        CustomAuthClient client,
        string redirectUri,
        string responseType,
        string scope,
        string codeChallenge,
        string codeChallengeMethod,
        string? state)
    {
        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
        {
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "unsupported_response_type",
                "Only response_type=code is supported.",
                state);
        }

        if (!IsScopeAllowed(client, scope))
        {
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_scope",
                "Requested scope is not allowed for this client.",
                state);
        }

        if ((_options.CurrentValue.RequirePkce || client.RequirePkce)
            && (string.IsNullOrWhiteSpace(codeChallenge) || string.IsNullOrWhiteSpace(codeChallengeMethod)))
        {
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_request",
                "PKCE code_challenge and code_challenge_method are required.",
                state);
        }

        if (!string.IsNullOrWhiteSpace(codeChallengeMethod) && !PkceVerifier.IsSupportedMethod(codeChallengeMethod))
        {
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_request",
                "Only S256 and plain PKCE methods are supported.",
                state);
        }

        return null;
    }

    private static bool IsScopeAllowed(CustomAuthClient client, string scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return true;
        }

        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return requestedScopes.All(requested => client.AllowedScopes.Contains(requested, StringComparer.Ordinal));
    }

    private string GetLoginUrl(HttpContext context)
    {
        var request = context.Request;
        var queryParams = QueryHelpers.ParseQuery(request.QueryString.ToString());
        var newQueryParams = new Dictionary<string, string?>();

        foreach (var param in queryParams)
        {
            if (string.Equals(param.Key, "prompt", StringComparison.OrdinalIgnoreCase))
            {
                var promptValues = param.Value.ToString()
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Where(v => !string.Equals(v, "login", StringComparison.OrdinalIgnoreCase));

                var newPrompt = string.Join(' ', promptValues);
                if (!string.IsNullOrEmpty(newPrompt))
                {
                    newQueryParams["prompt"] = newPrompt;
                }
            }
            else
            {
                newQueryParams[param.Key] = param.Value.ToString();
            }
        }

        var returnUrl = QueryHelpers.AddQueryString(request.PathBase + request.Path, newQueryParams);
        return QueryHelpers.AddQueryString(_options.CurrentValue.LoginPath, "returnUrl", returnUrl);
    }
}
