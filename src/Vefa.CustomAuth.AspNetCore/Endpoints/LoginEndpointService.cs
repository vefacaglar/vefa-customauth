using System.Net;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class LoginEndpointService
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IAntiforgery _antiforgery;
    private readonly ICustomAuthLoginAttemptTracker _loginAttemptTracker;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public LoginEndpointService(
        ICustomAuthUserStore userStore,
        ICustomAuthSessionManager sessionManager,
        SessionCookieService sessionCookieService,
        IAntiforgery antiforgery,
        ICustomAuthLoginAttemptTracker loginAttemptTracker,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _antiforgery = antiforgery ?? throw new ArgumentNullException(nameof(antiforgery));
        _loginAttemptTracker = loginAttemptTracker ?? throw new ArgumentNullException(nameof(loginAttemptTracker));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public IResult Render(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var returnUrl = context.Request.Query["returnUrl"].ToString();
        var tokens = _antiforgery.GetAndStoreTokens(context);
        return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, tokens, null), "text/html");
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            await _antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            var failedTokens = _antiforgery.GetAndStoreTokens(context);
            return Results.Content(
                RenderForm(string.Empty, _options.CurrentValue.LoginPath, failedTokens, "Your session has expired. Please try again."),
                "text/html",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var form = await context.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var userName = form["userName"].ToString();
        var password = form["password"].ToString();
        var returnUrl = form["returnUrl"].ToString();

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            var refreshedTokens = _antiforgery.GetAndStoreTokens(context);
            return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, refreshedTokens, "Username and password are required."), "text/html", statusCode: StatusCodes.Status400BadRequest);
        }

        if (await _loginAttemptTracker.IsBlockedAsync(userName, cancellationToken).ConfigureAwait(false))
        {
            var refreshedTokens = _antiforgery.GetAndStoreTokens(context);
            return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, refreshedTokens, "This account is temporarily locked due to too many failed login attempts."), "text/html", statusCode: StatusCodes.Status423Locked);
        }

        var user = await _userStore.ValidateCredentialsAsync(userName, password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            await _loginAttemptTracker.RecordFailureAsync(userName, cancellationToken).ConfigureAwait(false);
            var refreshedTokens = _antiforgery.GetAndStoreTokens(context);
            return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, refreshedTokens, "Invalid username or password."), "text/html", statusCode: StatusCodes.Status401Unauthorized);
        }

        await _loginAttemptTracker.RecordSuccessAsync(userName, cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        var session = new CustomAuthSession
        {
            Id = Guid.NewGuid(),
            UserId = user.UserId,
            CreatedAt = now,
            ExpiresAt = now.Add(_options.CurrentValue.RefreshTokenLifetime),
        };

        await _sessionManager.CreateAsync(session, cancellationToken).ConfigureAwait(false);
        _sessionCookieService.SignIn(context, session);

        return Results.Redirect(IsLocalReturnUrl(returnUrl) ? returnUrl : "/");
    }

    private static string RenderForm(string returnUrl, string loginPath, AntiforgeryTokenSet tokens, string? error)
    {
        var encodedReturnUrl = WebUtility.HtmlEncode(returnUrl);
        var encodedLoginPath = WebUtility.HtmlEncode(loginPath);
        var encodedFormFieldName = WebUtility.HtmlEncode(tokens.FormFieldName);
        var encodedRequestToken = WebUtility.HtmlEncode(tokens.RequestToken);
        var errorMarkup = string.IsNullOrWhiteSpace(error)
            ? string.Empty
            : $"<p>{WebUtility.HtmlEncode(error)}</p>";

        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Sign in</title>
            </head>
            <body>
                <main>
                    <h1>Sign in</h1>
                    {{errorMarkup}}
                    <form method="post" action="{{encodedLoginPath}}">
                        <input type="hidden" name="returnUrl" value="{{encodedReturnUrl}}">
                        <input type="hidden" name="{{encodedFormFieldName}}" value="{{encodedRequestToken}}">
                        <label>Username <input name="userName" autocomplete="username"></label>
                        <label>Password <input name="password" type="password" autocomplete="current-password"></label>
                        <button type="submit">Sign in</button>
                    </form>
                </main>
            </body>
            </html>
            """;
    }

    private static bool IsLocalReturnUrl(string returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
