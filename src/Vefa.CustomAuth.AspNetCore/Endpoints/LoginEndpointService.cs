using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
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
internal sealed partial class LoginEndpointService
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IAntiforgery _antiforgery;
    private readonly ICustomAuthLoginAttemptTracker _loginAttemptTracker;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<LoginEndpointService> _logger;

    public LoginEndpointService(
        ICustomAuthUserStore userStore,
        ICustomAuthSessionManager sessionManager,
        SessionCookieService sessionCookieService,
        IAntiforgery antiforgery,
        ICustomAuthLoginAttemptTracker loginAttemptTracker,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<LoginEndpointService> logger)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _antiforgery = antiforgery ?? throw new ArgumentNullException(nameof(antiforgery));
        _loginAttemptTracker = loginAttemptTracker ?? throw new ArgumentNullException(nameof(loginAttemptTracker));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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
        catch (AntiforgeryValidationException ex)
        {
            LogAntiforgeryFailed(returnUrl, ex);
            return RedirectToLoginPage(returnUrl, "antiforgery_failed");
        }

        var hasUserName = !string.IsNullOrWhiteSpace(userName);
        var hasPassword = !string.IsNullOrWhiteSpace(password);
        if (!hasUserName || !hasPassword)
        {
            var missingField = (hasUserName, hasPassword) switch
            {
                (false, false) => "userName and password",
                (false, true) => "userName",
                _ => "password",
            };
            LogMissingCredentials(missingField);
            return RedirectToLoginPage(returnUrl, "missing_credentials", userName);
        }

        if (await _loginAttemptTracker.IsBlockedAsync(userName, cancellationToken).ConfigureAwait(false))
        {
            LogAccountLocked(userName);
            return RedirectToLoginPage(returnUrl, "account_locked", userName);
        }

        var user = await _userStore.ValidateCredentialsAsync(userName, password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            await _loginAttemptTracker.RecordFailureAsync(userName, cancellationToken).ConfigureAwait(false);
            LogInvalidCredentials(userName);
            return RedirectToLoginPage(returnUrl, "invalid_credentials", userName);
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

        LogLoginSucceeded(userName, session.Id);
        return Results.Redirect(IsLocalReturnUrl(returnUrl) ? returnUrl : "/");
    }

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Warning,
        Message = "Login rejected: antiforgery validation failed (returnUrl: {ReturnUrl}).")]
    private partial void LogAntiforgeryFailed(string returnUrl, Exception exception);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Warning,
        Message = "Login rejected: missing credentials ({MissingField} not supplied).")]
    private partial void LogMissingCredentials(string missingField);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Warning,
        Message = "Login rejected: account is locked out due to too many failed attempts (userName: {UserName}).")]
    private partial void LogAccountLocked(string userName);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Warning,
        Message = "Login rejected: invalid credentials, the user name does not exist or the password is incorrect (userName: {UserName}).")]
    private partial void LogInvalidCredentials(string userName);

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Information,
        Message = "Login succeeded and SSO session opened (userName: {UserName}, sessionId: {SessionId}).")]
    private partial void LogLoginSucceeded(string userName, Guid sessionId);

    private IResult RedirectToLoginPage(string returnUrl, string errorCode, string? userName = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["error"] = errorCode,
        };
        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            query["returnUrl"] = returnUrl;
        }
        if (!string.IsNullOrWhiteSpace(userName))
        {
            query["userName"] = userName;
        }

        return Results.Redirect(QueryHelpers.AddQueryString(_options.CurrentValue.LoginPath, query));
    }

    private static bool IsLocalReturnUrl(string returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
