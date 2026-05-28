using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// Handles the credential-validation half of the login flow. UI rendering is the host's
/// responsibility; this service consumes a POST submission, validates antiforgery,
/// authenticates the user, opens an SSO session, and redirects.
/// </summary>
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

    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var form = await context.Request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var userName = form["userName"].ToString();
        var password = form["password"].ToString();
        var returnUrl = form["returnUrl"].ToString();

        try
        {
            await _antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            return RedirectToLoginPage(returnUrl, "antiforgery_failed");
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            return RedirectToLoginPage(returnUrl, "missing_credentials");
        }

        if (await _loginAttemptTracker.IsBlockedAsync(userName, cancellationToken).ConfigureAwait(false))
        {
            return RedirectToLoginPage(returnUrl, "account_locked");
        }

        var user = await _userStore.ValidateCredentialsAsync(userName, password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            await _loginAttemptTracker.RecordFailureAsync(userName, cancellationToken).ConfigureAwait(false);
            return RedirectToLoginPage(returnUrl, "invalid_credentials");
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

    private IResult RedirectToLoginPage(string returnUrl, string errorCode)
    {
        var query = new Dictionary<string, string?>
        {
            ["error"] = errorCode,
        };
        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            query["returnUrl"] = returnUrl;
        }

        return Results.Redirect(QueryHelpers.AddQueryString(_options.CurrentValue.LoginPath, query));
    }

    private static bool IsLocalReturnUrl(string returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
