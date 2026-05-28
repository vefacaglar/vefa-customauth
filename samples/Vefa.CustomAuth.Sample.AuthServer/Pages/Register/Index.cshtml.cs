using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages.Register;

/// <summary>
/// Host-owned user registration page model. Integrates with ASP.NET Core Identity
/// to create new users and flows them into the custom store.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly UserManager<IdentityUser>? _userManager;
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly SessionCookieService _sessionCookieService;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public IndexModel(
        ICustomAuthSessionManager sessionManager,
        SessionCookieService sessionCookieService,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        UserManager<IdentityUser>? userManager = null)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _sessionCookieService = sessionCookieService ?? throw new ArgumentNullException(nameof(sessionCookieService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _userManager = userManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Username is required.")]
    [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 100 characters.")]
    [RegularExpression(@"^[a-zA-Z0-9_\-\.]+$", ErrorMessage = "Username can only contain alphanumeric characters, underscores, hyphens, and periods.")]
    public string Username { get; set; } = string.Empty;

    [BindProperty]
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; } = string.Empty;

    [BindProperty]
    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 4, ErrorMessage = "Password must be at least 4 characters long.")]
    public string Password { get; set; } = string.Empty;

    [BindProperty]
    [Required(ErrorMessage = "Confirm password is required.")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }
    
    public bool IsIdentityEnabled => _userManager is not null;

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (_userManager is null)
        {
            ErrorMessage = "Registration is not supported because ASP.NET Core Identity is disabled in this environment.";
            return Page();
        }

        if (!ModelState.IsValid)
        {
            var firstError = ModelState.Values
                .SelectMany(v => v.Errors)
                .Select(e => e.ErrorMessage)
                .FirstOrDefault();
            ErrorMessage = firstError ?? "Please correct the errors in the form.";
            return Page();
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByNameAsync(Username).ConfigureAwait(false);
        if (existingUser is not null)
        {
            ErrorMessage = $"Username '{Username}' is already taken.";
            return Page();
        }

        var existingEmail = await _userManager.FindByEmailAsync(Email).ConfigureAwait(false);
        if (existingEmail is not null)
        {
            ErrorMessage = $"Email '{Email}' is already registered.";
            return Page();
        }

        var user = new IdentityUser
        {
            UserName = Username,
            Email = Email,
            EmailConfirmed = true
        };

        var result = await _userManager.CreateAsync(user, Password).ConfigureAwait(false);
        if (result.Succeeded)
        {
            // Direct Sign-In and SSO Session Creation
            var now = _timeProvider.GetUtcNow();
            var session = new CustomAuthSession
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                CreatedAt = now,
                ExpiresAt = now.Add(_options.CurrentValue.RefreshTokenLifetime),
            };

            await _sessionManager.CreateAsync(session, HttpContext.RequestAborted).ConfigureAwait(false);
            _sessionCookieService.SignIn(HttpContext, session);

            if (IsLocalReturnUrl(ReturnUrl))
            {
                return Redirect(ReturnUrl!);
            }
            return Redirect("/");
        }

        // Show the first error from Identity
        ErrorMessage = result.Errors.FirstOrDefault()?.Description ?? "Failed to create user.";
        return Page();
    }

    private static bool IsLocalReturnUrl(string? returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && returnUrl[0] == '/'
           && (returnUrl.Length == 1 || returnUrl[1] != '/')
           && !returnUrl.StartsWith("/\\", StringComparison.Ordinal);
}
