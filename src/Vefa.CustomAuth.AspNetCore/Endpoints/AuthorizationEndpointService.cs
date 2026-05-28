using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed partial class AuthorizationEndpointService
{
    private readonly ICustomAuthClientManager _clientManager;
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<AuthorizationEndpointService> _logger;

    public AuthorizationEndpointService(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        SessionCookieService sessionCookieService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<AuthorizationEndpointService> logger)
    {
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
            LogMissingClientId();
            return EndpointResults.OAuthError("invalid_request", "client_id is required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId);
            return EndpointResults.OAuthError("unauthorized_client", "The client is not registered.");
        }

        if (string.IsNullOrWhiteSpace(redirectUri) || !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            LogRedirectUriMismatch(
                clientId,
                string.IsNullOrWhiteSpace(redirectUri) ? "(none)" : redirectUri,
                string.Join(", ", client.RedirectUris));
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
            LogInvalidPromptCombination(clientId, prompt ?? string.Empty);
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
                LogLoginRequired(clientId);
                return EndpointResults.OAuthAuthorizeRedirectError(
                    redirectUri,
                    "login_required",
                    "The user is not authenticated and prompt=none was requested.",
                    state);
            }

            LogRedirectingToLogin(clientId);
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

        LogAuthorizationCodeIssued(client.ClientId, scope);
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
            LogUnsupportedResponseType(client.ClientId, string.IsNullOrEmpty(responseType) ? "(none)" : responseType);
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "unsupported_response_type",
                "Only response_type=code is supported.",
                state);
        }

        if (!IsScopeAllowed(client, scope))
        {
            LogInvalidScope(client.ClientId, scope, string.Join(", ", client.AllowedScopes));
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_scope",
                "Requested scope is not allowed for this client.",
                state);
        }

        if ((_options.CurrentValue.RequirePkce || client.RequirePkce)
            && (string.IsNullOrWhiteSpace(codeChallenge) || string.IsNullOrWhiteSpace(codeChallengeMethod)))
        {
            LogPkceRequired(client.ClientId);
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_request",
                "PKCE code_challenge and code_challenge_method are required.",
                state);
        }

        if (!string.IsNullOrWhiteSpace(codeChallengeMethod) && !PkceVerifier.IsSupportedMethod(codeChallengeMethod))
        {
            LogUnsupportedPkceMethod(client.ClientId, codeChallengeMethod);
            return EndpointResults.OAuthAuthorizeRedirectError(
                redirectUri,
                "invalid_request",
                "Only S256 PKCE method is supported.",
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

    // Authorization endpoint diagnostics. Event IDs 2100-2199. Only non-secret request metadata is
    // logged (client_id, redirect_uri, scope, prompt, response_type); never codes or tokens.

    [LoggerMessage(EventId = 2100, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_request): client_id is missing.")]
    private partial void LogMissingClientId();

    [LoggerMessage(EventId = 2101, Level = LogLevel.Warning,
        Message = "Authorize request rejected (unauthorized_client): client '{ClientId}' is not registered.")]
    private partial void LogUnknownClient(string clientId);

    [LoggerMessage(EventId = 2102, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_request): redirect_uri '{RequestRedirectUri}' does not exactly match any registered redirect URI for client '{ClientId}'. Registered: [{RegisteredRedirectUris}]. Matching is case-sensitive and exact (scheme, host, port, path, trailing slash all count).")]
    private partial void LogRedirectUriMismatch(string clientId, string requestRedirectUri, string registeredRedirectUris);

    [LoggerMessage(EventId = 2103, Level = LogLevel.Warning,
        Message = "Authorize request rejected (unsupported_response_type): response_type '{ResponseType}' is not supported; only 'code' is allowed (client: {ClientId}).")]
    private partial void LogUnsupportedResponseType(string clientId, string responseType);

    [LoggerMessage(EventId = 2104, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_scope): requested scope '{RequestedScope}' contains values not allowed for client '{ClientId}'. Allowed: [{AllowedScopes}].")]
    private partial void LogInvalidScope(string clientId, string requestedScope, string allowedScopes);

    [LoggerMessage(EventId = 2105, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_request): PKCE is required but code_challenge/code_challenge_method were not supplied (client: {ClientId}).")]
    private partial void LogPkceRequired(string clientId);

    [LoggerMessage(EventId = 2106, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_request): unsupported PKCE method '{Method}'; only 'S256' is allowed (client: {ClientId}).")]
    private partial void LogUnsupportedPkceMethod(string clientId, string method);

    [LoggerMessage(EventId = 2107, Level = LogLevel.Warning,
        Message = "Authorize request rejected (invalid_request): prompt='{Prompt}' combines 'none' with other values (client: {ClientId}).")]
    private partial void LogInvalidPromptCombination(string clientId, string prompt);

    [LoggerMessage(EventId = 2108, Level = LogLevel.Information,
        Message = "Authorize request returned login_required: no active session and prompt=none was requested (client: {ClientId}).")]
    private partial void LogLoginRequired(string clientId);

    [LoggerMessage(EventId = 2109, Level = LogLevel.Information,
        Message = "Authorize request has no active session; redirecting to the login page (client: {ClientId}).")]
    private partial void LogRedirectingToLogin(string clientId);

    [LoggerMessage(EventId = 2110, Level = LogLevel.Information,
        Message = "Authorization code issued (client: {ClientId}, scope: '{Scope}').")]
    private partial void LogAuthorizationCodeIssued(string clientId, string scope);
}
