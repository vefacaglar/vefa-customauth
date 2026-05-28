using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages.ResetPassword;

/// <summary>
/// Host-owned password reset confirmation page model. Integrates with ASP.NET Core Identity
/// to consume the reset token and update the user's password.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly UserManager<IdentityUser>? _userManager;

    public IndexModel(UserManager<IdentityUser>? userManager = null)
    {
        _userManager = userManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? Email { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Token { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 4, ErrorMessage = "Password must be at least 4 characters long.")]
    public string NewPassword { get; set; } = string.Empty;

    [BindProperty]
    [Required(ErrorMessage = "Confirm password is required.")]
    [DataType(DataType.Password)]
    [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmNewPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }

    public bool IsIdentityEnabled => _userManager is not null;

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(Email) || string.IsNullOrWhiteSpace(Token))
        {
            ErrorMessage = "Invalid password reset request. Email and token are required.";
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (_userManager is null)
        {
            ErrorMessage = "Password reset is not supported because ASP.NET Core Identity is disabled in this environment.";
            return Page();
        }

        if (string.IsNullOrWhiteSpace(Email) || string.IsNullOrWhiteSpace(Token))
        {
            ErrorMessage = "Invalid password reset request. Email and token are required.";
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

        var user = await _userManager.FindByEmailAsync(Email).ConfigureAwait(false);
        if (user is null)
        {
            ErrorMessage = "User not found.";
            return Page();
        }

        var result = await _userManager.ResetPasswordAsync(user, Token, NewPassword).ConfigureAwait(false);
        if (result.Succeeded)
        {
            return RedirectToPage("/Login/Index", new { resetSuccess = true, returnUrl = ReturnUrl });
        }

        // Show the first error from Identity
        ErrorMessage = result.Errors.FirstOrDefault()?.Description ?? "Failed to reset password. The token may be invalid or expired.";
        return Page();
    }
}
