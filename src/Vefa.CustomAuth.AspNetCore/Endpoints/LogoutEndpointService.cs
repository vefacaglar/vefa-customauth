using System.Net;
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

internal sealed class LogoutEndpointService
{
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly ICustomAuthClientManager _clientManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly ISigningCredentialsProvider _signingCredentialsProvider;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly IAntiforgery _antiforgery;
    private readonly TimeProvider _timeProvider;

    public LogoutEndpointService(
        ICustomAuthSessionManager sessionManager,
        ICustomAuthClientManager clientManager,
        SessionCookieService sessionCookieService,
        ISigningCredentialsProvider signingCredentialsProvider,
        IOptionsMonitor<CustomAuthOptions> options,
        IAntiforgery antiforgery,
        TimeProvider timeProvider)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _signingCredentialsProvider = signingCredentialsProvider ?? throw new ArgumentNullException(nameof(signingCredentialsProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _antiforgery = antiforgery ?? throw new ArgumentNullException(nameof(antiforgery));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // 1. Parse request parameters (accept both GET query and POST form)
        var request = context.Request;
        var idTokenHint = request.Method == HttpMethods.Post
            ? request.Form["id_token_hint"].ToString()
            : request.Query["id_token_hint"].ToString();

        var postLogoutRedirectUri = request.Method == HttpMethods.Post
            ? request.Form["post_logout_redirect_uri"].ToString()
            : request.Query["post_logout_redirect_uri"].ToString();

        var state = request.Method == HttpMethods.Post
            ? request.Form["state"].ToString()
            : request.Query["state"].ToString();

        var clientIdParam = request.Method == HttpMethods.Post
            ? request.Form["client_id"].ToString()
            : request.Query["client_id"].ToString();

        // 2. Cryptographically validate id_token_hint to discover the client ID
        string? clientId = null;
        var hasValidIdTokenHint = false;
        if (!string.IsNullOrWhiteSpace(idTokenHint))
        {
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
                        ValidateAudience = false, // We don't validate specific audience in order to read it
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKeys = jwks,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromMinutes(5),
                    }).ConfigureAwait(false);

                if (validationResult.IsValid)
                {
                    clientId = validationResult.ClaimsIdentity.FindFirst("client_id")?.Value
                        ?? validationResult.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;
                    hasValidIdTokenHint = !string.IsNullOrWhiteSpace(clientId);
                }
            }
            catch
            {
                // Invalid id_token_hint signature or expired; proceed securely without redirect validation
            }
        }

        // Fallback to client_id parameter if id_token_hint validation did not yield a client ID
        if (string.IsNullOrWhiteSpace(clientId))
        {
            clientId = clientIdParam;
        }

        // 3. Security checks for GET vs POST
        if (HttpMethods.IsGet(request.Method))
        {
            if (!hasValidIdTokenHint)
            {
                // Serve the secure Logout Confirmation page
                var antiforgeryToken = _antiforgery.GetAndStoreTokens(context);
                return Results.Content(GetConfirmationHtml(antiforgeryToken.RequestToken!, postLogoutRedirectUri, state, clientIdParam), "text/html");
            }
        }
        else if (HttpMethods.IsPost(request.Method))
        {
            if (!hasValidIdTokenHint)
            {
                // Validate Antiforgery token
                try
                {
                    await _antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
                }
                catch (AntiforgeryValidationException)
                {
                    return Results.BadRequest("Antiforgery token validation failed.");
                }
            }
        }

        // 4. Terminate the active SSO session if present (only when intent is confirmed!)
        var session = await _sessionCookieService.GetCurrentSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session is not null)
        {
            await _sessionManager.RevokeAsync(session.Id, cancellationToken).ConfigureAwait(false);
        }

        // Clear the cookie anyway
        _sessionCookieService.SignOut(context);

        // 5. Validate post_logout_redirect_uri against registered client config
        var isValidRedirect = false;
        if (!string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
            if (client is not null && client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri, StringComparer.Ordinal))
            {
                isValidRedirect = true;
            }
        }

        if (isValidRedirect && !string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            var redirectUrl = postLogoutRedirectUri;
            if (!string.IsNullOrEmpty(state))
            {
                redirectUrl = QueryHelpers.AddQueryString(redirectUrl, "state", state);
            }
            return Results.Redirect(redirectUrl);
        }

        // 6. Render premium, gorgeous minimalistic success HTML
        var template = LoadTemplate("logged-out.html");
        return Results.Content(template, "text/html");
    }

    private static string LoadTemplate(string resourceName)
    {
        var assembly = typeof(LogoutEndpointService).Assembly;
        using var stream = assembly.GetManifestResourceStream($"Vefa.CustomAuth.AspNetCore.Resources.{resourceName}");
        if (stream is null)
        {
            throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        }
        using var reader = new System.IO.StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static string GetConfirmationHtml(string antiforgeryToken, string postLogoutRedirectUri, string state, string clientId)
    {
        var template = LoadTemplate("logout-confirm.html");
        return template
            .Replace("{antiforgeryToken}", antiforgeryToken, StringComparison.Ordinal)
            .Replace("{postLogoutRedirectUri}", WebUtility.HtmlEncode(postLogoutRedirectUri), StringComparison.Ordinal)
            .Replace("{state}", WebUtility.HtmlEncode(state), StringComparison.Ordinal)
            .Replace("{clientId}", WebUtility.HtmlEncode(clientId), StringComparison.Ordinal);
    }
}
