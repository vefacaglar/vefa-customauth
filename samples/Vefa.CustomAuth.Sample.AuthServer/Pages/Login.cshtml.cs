using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages;

/// <summary>
/// Backend model for custom, Razor Pages-driven login screen in Sample.AuthServer.
/// </summary>
public sealed class LoginModel : PageModel
{
    private readonly ICustomAuthUserStore _userStore;
    private readonly ICustomAuthLoginAttemptTracker _loginAttemptTracker;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginModel"/> class.
    /// </summary>
    public LoginModel(
        ICustomAuthUserStore userStore,
        ICustomAuthLoginAttemptTracker loginAttemptTracker)
    {
        _userStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        _loginAttemptTracker = loginAttemptTracker ?? throw new ArgumentNullException(nameof(loginAttemptTracker));
    }

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    [BindProperty]
    [Required(ErrorMessage = "Username is required.")]
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    [BindProperty]
    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the secure redirection return URL.
    /// </summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// Gets or sets error message to display in the UI.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Handles GET request.
    /// </summary>
    public void OnGet()
    {
    }

    /// <summary>
    /// Handles POST request securely.
    /// </summary>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (await _loginAttemptTracker.IsBlockedAsync(UserName, cancellationToken).ConfigureAwait(false))
        {
            ErrorMessage = "This account is temporarily locked due to too many failed login attempts.";
            return Page();
        }

        var user = await _userStore.ValidateCredentialsAsync(UserName, Password, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            await _loginAttemptTracker.RecordFailureAsync(UserName, cancellationToken).ConfigureAwait(false);
            ErrorMessage = "Invalid username or password.";
            return Page();
        }

        await _loginAttemptTracker.RecordSuccessAsync(UserName, cancellationToken).ConfigureAwait(false);

        // Sign in using our beautiful and elegant new HttpContext extension method!
        await HttpContext.SignInCustomAuthAsync(user.UserId, cancellationToken).ConfigureAwait(false);

        if (IsLocalReturnUrl(ReturnUrl))
        {
            return Redirect(ReturnUrl!);
        }

        return Redirect("~/");
    }

    private static bool IsLocalReturnUrl(string? returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
