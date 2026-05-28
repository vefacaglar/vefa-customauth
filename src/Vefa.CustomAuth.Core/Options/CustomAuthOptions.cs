namespace Vefa.CustomAuth.Core.Options;

/// <summary>
/// Configures the core behavior of the Vefa.CustomAuth authorization server.
/// </summary>
public sealed class CustomAuthOptions
{
    /// <summary>
    /// Gets or sets the absolute issuer URI used in discovery metadata and issued tokens.
    /// </summary>
    public string Issuer { get; set; } = default!;

    /// <summary>
    /// Gets or sets the authorization code lifetime.
    /// </summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Gets or sets the access token lifetime.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the ID token lifetime.
    /// </summary>
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the refresh token lifetime.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Gets or sets the login path used when an authorization request requires interactive sign-in.
    /// </summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Gets or sets the SSO session cookie name.
    /// </summary>
    public string CookieName { get; set; } = ".Vefa.CustomAuth.Session";

    /// <summary>
    /// Gets or sets a value indicating whether PKCE is required for authorization code requests.
    /// </summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS is required for the issuer URI.
    /// </summary>
    public bool RequireHttps { get; set; } = true;
}
