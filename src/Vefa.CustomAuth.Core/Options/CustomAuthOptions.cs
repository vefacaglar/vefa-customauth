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
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Gets or sets the access token lifetime.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the ID token lifetime.
    /// </summary>
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the sliding refresh token lifetime.
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Gets or sets the maximum lifetime of a refresh token chain.
    /// Rotation does not extend this lifetime.
    /// </summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// Gets or sets a value indicating whether refresh token reuse should revoke the related token chain.
    /// </summary>
    public bool DetectRefreshTokenReuse { get; set; } = true;

    /// <summary>
    /// Gets or sets the path to the host-provided login page. The authorization endpoint
    /// redirects unauthenticated users here with a <c>returnUrl</c> query parameter.
    /// The host owns this page (Razor Pages, MVC, Blazor, etc.) and is expected to
    /// call <see cref="Vefa.CustomAuth.AspNetCore.Extensions.CustomAuthHttpContextExtensions.SignInCustomAuthAsync"/>
    /// once the user has authenticated.
    /// </summary>
    public string LoginPath { get; set; } = "/login";

    /// <summary>
    /// Gets or sets the path to the host-provided logout confirmation page. The
    /// <c>/connect/logout</c> endpoint redirects here when an end-session request
    /// arrives without a cryptographically valid <c>id_token_hint</c>, so the host
    /// can confirm user intent before terminating the session.
    /// </summary>
    public string LogoutPath { get; set; } = "/logout";

    /// <summary>
    /// Gets or sets the fallback redirect target the library uses after a successful logout
    /// when no <c>post_logout_redirect_uri</c> was supplied (or the supplied one is not registered).
    /// The host owns this page if it wants to render a "you have been signed out" screen.
    /// </summary>
    public string PostLogoutRedirectUri { get; set; } = "/";

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
