namespace Vefa.CustomAuth.Core.Options;

public sealed class CustomAuthOptions
{
    public string Issuer { get; set; } = default!;

    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    public string LoginPath { get; set; } = "/login";
    public string CookieName { get; set; } = ".Vefa.CustomAuth.Session";

    public bool RequirePkce { get; set; } = true;
    public bool RequireHttps { get; set; } = true;
}
