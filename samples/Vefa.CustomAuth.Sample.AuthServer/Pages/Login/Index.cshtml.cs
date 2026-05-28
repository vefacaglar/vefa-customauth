using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.AspNetCore.Extensions;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages.Login;

/// <summary>
/// Host-owned login page. Fully owns UI rendering and the credential-validation POST action.
/// Once the user is successfully authenticated, it creates the SSO session and sets the
/// cookie via <see cref="CustomAuthHttpContextExtensions.SignInCustomAuthAsync"/>.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthLoginAttemptTracker _loginAttemptTracker;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(
        ICustomAuthUserStore userStore,
        ICustomAuthLoginAttemptTracker loginAttemptTracker,
        ILogger<IndexModel> logger)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _loginAttemptTracker = loginAttemptTracker ?? throw new ArgumentNullException(nameof(loginAttemptTracker));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? UserName { get; set; }

    [BindProperty]
    public string? Password { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool? Registered { get; set; }

    [BindProperty(SupportsGet = true)]
    public bool? ResetSuccess { get; set; }

    [BindProperty(SupportsGet = true, Name = "error")]
    public string? ErrorCode { get; set; }

    public string? ErrorMessage => ErrorCode switch
    {
        "invalid_credentials" => "Invalid username or password.",
        "missing_credentials" => "Username and password are required.",
        "account_locked" => "This account is temporarily locked due to too many failed login attempts.",
        "antiforgery_failed" => "Your session has expired. Please try again.",
        _ => null,
    };

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        var returnUrl = ReturnUrl ?? "/";
        var userName = UserName;
        var password = Password;

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(password))
        {
            ErrorCode = "missing_credentials";
            return Page();
        }

        if (await _loginAttemptTracker.IsBlockedAsync(userName, cancellationToken).ConfigureAwait(false))
        {
            ErrorCode = "account_locked";
            return Page();
        }

        var user = await _userStore.ValidateCredentialsAsync(userName, password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            await _loginAttemptTracker.RecordFailureAsync(userName, cancellationToken).ConfigureAwait(false);
            ErrorCode = "invalid_credentials";
            return Page();
        }

        await _loginAttemptTracker.RecordSuccessAsync(userName, cancellationToken).ConfigureAwait(false);

        // Sign the user in by establishing the SSO session and setting the cookie
        await HttpContext.SignInCustomAuthAsync(user.UserId, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("User logged in successfully (UserName: {UserName}). Redirecting to {ReturnUrl}", userName, returnUrl);

        if (IsLocalReturnUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }
        return Redirect("~/");
    }

    private static bool IsLocalReturnUrl(string returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
