namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a configured OAuth2 / OIDC scope.
/// </summary>
public sealed class CustomAuthScope
{
    /// <summary>
    /// Gets or sets the unique name of the scope (e.g., "openid", "profile").
    /// </summary>
    public string Name { get; set; } = default!;

    /// <summary>
    /// Gets or sets the friendly display name.
    /// </summary>
    public string? DisplayName { get; set; }

    /// <summary>
    /// Gets or sets the detailed description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this scope is required and cannot be deselected by the user.
    /// </summary>
    public bool Required { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this scope should be highlighted or emphasized on consent screens.
    /// </summary>
    public bool Emphasize { get; set; }
}
