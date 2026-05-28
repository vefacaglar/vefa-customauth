using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// Implements the OIDC RP-Initiated Logout endpoint. UI rendering is the host's
/// responsibility: when an end-session request arrives without a cryptographically
/// valid <c>id_token_hint</c>, the user is redirected to the host's confirmation page;
/// when intent is confirmed, the SSO session is terminated and the user is redirected
/// to the (validated) <c>post_logout_redirect_uri</c> or to <c>PostLogoutRedirectUri</c>.
/// </summary>
internal sealed class LogoutEndpointService
{
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly ICustomAuthClientManager _clientManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly ISigningCredentialsProvider _signingCredentialsProvider;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly IAntiforgery _antiforgery;

    public LogoutEndpointService(
        ICustomAuthSessionManager sessionManager,
        ICustomAuthClientManager clientManager,
        SessionCookieService sessionCookieService,
        ISigningCredentialsProvider signingCredentialsProvider,
        IOptionsMonitor<CustomAuthOptions> options,
        IAntiforgery antiforgery)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _signingCredentialsProvider = signingCredentialsProvider ?? throw new ArgumentNullException(nameof(signingCredentialsProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _antiforgery = antiforgery ?? throw new ArgumentNullException(nameof(antiforgery));
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;
        var isPost = HttpMethods.IsPost(request.Method);

        var idTokenHint = ReadParameter(request, "id_token_hint", isPost);
        var postLogoutRedirectUri = ReadParameter(request, "post_logout_redirect_uri", isPost);
        var state = ReadParameter(request, "state", isPost);
        var clientIdParam = ReadParameter(request, "client_id", isPost);

        var (clientIdFromHint, hasValidIdTokenHint) = await TryReadClientIdFromIdTokenHintAsync(idTokenHint, cancellationToken).ConfigureAwait(false);
        var clientId = !string.IsNullOrWhiteSpace(clientIdFromHint) ? clientIdFromHint : clientIdParam;

        if (!hasValidIdTokenHint)
        {
            if (isPost)
            {
                try
                {
                    await _antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
                }
                catch (AntiforgeryValidationException)
                {
                    return Results.BadRequest("Antiforgery token validation failed.");
                }
            }
            else
            {
                return RedirectToLogoutPage(postLogoutRedirectUri, state, clientIdParam);
            }
        }

        var session = await _sessionCookieService.GetCurrentSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session is not null)
        {
            await _sessionManager.RevokeAsync(session.Id, cancellationToken).ConfigureAwait(false);
        }

        _sessionCookieService.SignOut(context);

        if (!string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
            if (client is not null && client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri, StringComparer.Ordinal))
            {
                var redirectUrl = postLogoutRedirectUri;
                if (!string.IsNullOrEmpty(state))
                {
                    redirectUrl = QueryHelpers.AddQueryString(redirectUrl, "state", state);
                }
                return Results.Redirect(redirectUrl);
            }
        }

        return Results.Redirect(_options.CurrentValue.PostLogoutRedirectUri);
    }

    private IResult RedirectToLogoutPage(string postLogoutRedirectUri, string state, string clientId)
    {
        var query = new Dictionary<string, string?>();
        if (!string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            query["post_logout_redirect_uri"] = postLogoutRedirectUri;
        }
        if (!string.IsNullOrWhiteSpace(state))
        {
            query["state"] = state;
        }
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            query["client_id"] = clientId;
        }

        var target = _options.CurrentValue.LogoutPath;
        return Results.Redirect(query.Count == 0 ? target : QueryHelpers.AddQueryString(target, query));
    }

    private async Task<(string? ClientId, bool IsValid)> TryReadClientIdFromIdTokenHintAsync(string idTokenHint, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(idTokenHint))
        {
            return (null, false);
        }

        try
        {
            var jwks = await _signingCredentialsProvider.GetJsonWebKeySetAsync(cancellationToken).ConfigureAwait(false);
            var handler = new JsonWebTokenHandler();
            var validationResult = await handler.ValidateTokenAsync(
                idTokenHint,
                new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = _options.CurrentValue.Issuer,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = jwks,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(5),
                }).ConfigureAwait(false);

            if (!validationResult.IsValid)
            {
                return (null, false);
            }

            var clientId = validationResult.ClaimsIdentity.FindFirst("client_id")?.Value
                ?? validationResult.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;

            return string.IsNullOrWhiteSpace(clientId) ? (null, false) : (clientId, true);
        }
        catch
        {
            return (null, false);
        }
    }

    private static string ReadParameter(HttpRequest request, string name, bool isPost)
        => isPost ? request.Form[name].ToString() : request.Query[name].ToString();
}
