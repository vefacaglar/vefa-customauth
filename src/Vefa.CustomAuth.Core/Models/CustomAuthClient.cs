namespace Vefa.CustomAuth.Core.Models;

public sealed class CustomAuthClient
{
    public string ClientId { get; set; } = default!;
    public string DisplayName { get; set; } = default!;

    public List<string> RedirectUris { get; set; } = new();
    public List<string> PostLogoutRedirectUris { get; set; } = new();

    public List<string> AllowedScopes { get; set; } = new();

    public bool RequirePkce { get; set; } = true;
    public bool AllowRefreshTokens { get; set; } = true;

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;
}
