using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Vefa.CustomAuth.Sample.AuthServer.Pages;

/// <summary>
/// Host-owned logout confirmation page. The library redirects here when an end-session
/// request arrives without a verifiable <c>id_token_hint</c>. The form posts back to
/// <c>/connect/logout</c> (with antiforgery + forwarded parameters) so the library can
/// terminate the session.
/// </summary>
public sealed class LogoutModel : PageModel
{
    [BindProperty(SupportsGet = true, Name = "post_logout_redirect_uri")]
    public string? PostLogoutRedirectUri { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? State { get; set; }

    [BindProperty(SupportsGet = true, Name = "client_id")]
    public string? ClientId { get; set; }

    public void OnGet()
    {
    }
}
