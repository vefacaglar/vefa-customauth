using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class LoginEndpointService
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public LoginEndpointService(
        ICustomAuthUserStore userStore,
        ICustomAuthSessionManager sessionManager,
        SessionCookieService sessionCookieService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public IResult Render(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var returnUrl = request.Query["returnUrl"].ToString();
        return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, null), "text/html");
    }

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var form = await context.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var userName = form["userName"].ToString();
        var password = form["password"].ToString();
        var returnUrl = form["returnUrl"].ToString();

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, "Username and password are required."), "text/html", statusCode: StatusCodes.Status400BadRequest);
        }

        var user = await _userStore.ValidateCredentialsAsync(userName, password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return Results.Content(RenderForm(returnUrl, _options.CurrentValue.LoginPath, "Invalid username or password."), "text/html", statusCode: StatusCodes.Status401Unauthorized);
        }

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

    private static string RenderForm(string returnUrl, string loginPath, string? error)
    {
        var encodedReturnUrl = WebUtility.HtmlEncode(returnUrl);
        var encodedLoginPath = WebUtility.HtmlEncode(loginPath);
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
