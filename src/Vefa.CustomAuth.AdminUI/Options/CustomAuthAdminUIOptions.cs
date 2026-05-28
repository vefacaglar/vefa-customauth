namespace Vefa.CustomAuth.AdminUI.Options;

/// <summary>
/// Configures the embedded Vefa.CustomAuth Admin UI endpoints.
/// </summary>
public sealed class CustomAuthAdminUIOptions
{
    /// <summary>
    /// Gets or sets the URL path prefix where the Admin UI is hosted.
    /// </summary>
    public string PathPrefix { get; set; } = "/customauth";

    /// <summary>
    /// Gets or sets the default page size used by paged Admin UI APIs.
    /// </summary>
    public int DefaultPageSize { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum page size accepted by paged Admin UI APIs.
    /// </summary>
    public int MaxPageSize { get; set; } = 100;

    /// <summary>
    /// Gets or sets the name of the authorization policy applied to all Admin UI routes.
    /// When <c>null</c> (the default), the framework's default authorization policy is applied.
    /// </summary>
    /// <remarks>
    /// Ignored when <see cref="AllowAnonymous"/> is <c>true</c>.
    /// </remarks>
    public string? AuthorizationPolicyName { get; set; }

    /// <summary>
    /// Opts out of the built-in authorization requirement on Admin UI routes.
    /// Defaults to <c>false</c> so the dashboard and admin APIs are protected by default.
    /// </summary>
    /// <remarks>
    /// Only set this to <c>true</c> for local development, automated tests, or
    /// environments where access to the Admin UI is restricted by network controls.
    /// Enabling this in production exposes administrative endpoints (client CRUD,
    /// session and refresh-token revocation, signing-key viewer) to anonymous callers.
    /// </remarks>
    public bool AllowAnonymous { get; set; }
}
