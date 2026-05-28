namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents one allowed authorization redirect URI for a client.
/// </summary>
public sealed class CustomAuthClientRedirectUri
{
    /// <summary>
    /// Gets or sets the client identifier that owns the redirect URI.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the exact redirect URI value.
    /// </summary>
    public string Uri { get; set; } = default!;
}
