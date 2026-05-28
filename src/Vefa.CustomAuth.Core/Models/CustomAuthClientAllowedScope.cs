namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents one scope that a client is allowed to request.
/// </summary>
public sealed class CustomAuthClientAllowedScope
{
    /// <summary>
    /// Gets or sets the client identifier that owns the allowed scope.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the allowed scope name.
    /// </summary>
    public string Scope { get; set; } = default!;
}
