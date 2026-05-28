using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace Vefa.CustomAuth.Sample.WebApp.Pages;

public class IndexModel : PageModel
{
    public string Name { get; set; } = "User";
    public string Initials { get; set; } = "U";
    public bool IsAuthenticated { get; set; }

    public void OnGet()
    {
        IsAuthenticated = User.Identity?.IsAuthenticated == true;
        if (IsAuthenticated)
        {
            Name = User.Identity?.Name ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value ?? "User";
            Initials = Name.Length > 0 ? Name.Substring(0, 1).ToUpperInvariant() : "U";
        }
    }
}
