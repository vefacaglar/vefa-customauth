using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages;

/// <summary>
/// Host-owned login page. The form posts to <c>/login</c>, which the library handles
/// (antiforgery validation, credential check, session creation, redirect). This page
/// only renders the form and surfaces error codes the library appended to the query
/// string after a failed attempt.
/// </summary>
public sealed class LoginModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

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
}
