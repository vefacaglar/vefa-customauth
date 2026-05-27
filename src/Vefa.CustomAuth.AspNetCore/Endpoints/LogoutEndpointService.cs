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
    private readonly TimeProvider _timeProvider;

    public LogoutEndpointService(
        ICustomAuthSessionManager sessionManager,
        ICustomAuthClientManager clientManager,
        SessionCookieService sessionCookieService,
        ISigningCredentialsProvider signingCredentialsProvider,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _signingCredentialsProvider = signingCredentialsProvider ?? throw new ArgumentNullException(nameof(signingCredentialsProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // 1. Terminate the active SSO session if present
        var session = await _sessionCookieService.GetCurrentSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session is not null)
        {
            await _sessionManager.RevokeAsync(session.Id, cancellationToken).ConfigureAwait(false);
        }

        // Clear the cookie anyway
        _sessionCookieService.SignOut(context);

        // 2. Parse request parameters (accept both GET query and POST form)
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

        // 3. Cryptographically validate id_token_hint to discover the client ID
        string? clientId = null;
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

        // 4. Validate post_logout_redirect_uri against registered client config
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

        // 5. Render premium, gorgeous minimalistic success HTML
        var html = @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Logged Out</title>
    <link href=""https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap"" rel=""stylesheet"">
    <style>
        :root {
            --bg-color: #0d0f12;
            --card-bg: rgba(20, 24, 33, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #ffffff;
            --text-secondary: #8e9cae;
            --accent-color: #3b82f6;
            --accent-gradient: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
        }
        body {
            margin: 0;
            padding: 0;
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Outfit', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            overflow: hidden;
        }
        .container {
            position: relative;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 3rem 2.5rem;
            border-radius: 24px;
            backdrop-filter: blur(16px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
            text-align: center;
            max-width: 420px;
            width: 90%;
            z-index: 1;
        }
        .glow {
            position: absolute;
            width: 250px;
            height: 250px;
            background: var(--accent-color);
            filter: blur(120px);
            opacity: 0.15;
            border-radius: 50%;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            z-index: 0;
        }
        .icon {
            width: 64px;
            height: 64px;
            background: var(--accent-gradient);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
            box-shadow: 0 8px 16px rgba(59, 130, 246, 0.25);
        }
        .icon svg {
            width: 32px;
            height: 32px;
            fill: none;
            stroke: #ffffff;
            stroke-width: 2.5;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        h1 {
            font-size: 2rem;
            font-weight: 600;
            margin: 0 0 0.5rem;
            letter-spacing: -0.5px;
        }
        p {
            color: var(--text-secondary);
            font-size: 1rem;
            line-height: 1.6;
            margin: 0 0 2rem;
        }
        .btn {
            display: inline-block;
            text-decoration: none;
            background: var(--accent-gradient);
            color: #ffffff;
            padding: 0.8rem 2rem;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.95rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
        }
    </style>
</head>
<body>
    <div class=""glow""></div>
    <div class=""container"">
        <div class=""icon"">
            <svg viewBox=""0 0 24 24"">
                <path d=""M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4""></path>
                <polyline points=""16 17 21 12 16 7""></polyline>
                <line x1=""21"" y1=""12"" x2=""9"" y2=""12""></line>
            </svg>
        </div>
        <h1>Logged Out Successfully</h1>
        <p>Your session has been terminated securely. You can now close this tab or return to the application.</p>
        <a href=""/"" class=""btn"">Go to Home</a>
    </div>
</body>
</html>";

        return Results.Content(html, "text/html");
    }
}
