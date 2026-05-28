using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages.ForgotPassword;

/// <summary>
/// Host-owned forgot password page model. Generates secure password reset tokens
/// using ASP.NET Core Identity.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly UserManager<IdentityUser>? _userManager;

    public IndexModel(UserManager<IdentityUser>? userManager = null)
    {
        _userManager = userManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public string Email { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }
    
    public bool Submitted { get; set; }
    
    public string? ResetLink { get; set; }

    public bool IsIdentityEnabled => _userManager is not null;

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (_userManager is null)
        {
            ErrorMessage = "Password reset is not supported because ASP.NET Core Identity is disabled in this environment.";
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
        if (user is not null)
        {
            // Generate secure reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
            
            // Build the reset link absolute URL pointing to /ResetPassword Razor page
            ResetLink = Url.Page(
                "/ResetPassword/Index",
                pageHandler: null,
                values: new { email = Email, token = token, returnUrl = ReturnUrl },
                protocol: Request.Scheme
            );

            // Log it to the console for reference
            Console.WriteLine("==================================================");
            Console.WriteLine($"[DEMO ONLY] PASSWORD RESET LINK generated for {Email}:");
            Console.WriteLine(ResetLink);
            Console.WriteLine("==================================================");
        }

        Submitted = true;
        return Page();
    }
}
