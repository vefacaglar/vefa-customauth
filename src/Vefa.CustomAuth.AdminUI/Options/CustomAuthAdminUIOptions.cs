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
}
