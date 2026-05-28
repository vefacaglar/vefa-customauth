namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents one allowed post-logout redirect URI for a client.
/// </summary>
public sealed class CustomAuthClientPostLogoutRedirectUri
{
    /// <summary>
    /// Gets or sets the client identifier that owns the post-logout redirect URI.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the exact post-logout redirect URI value.
    /// </summary>
    public string Uri { get; set; } = default!;
}
