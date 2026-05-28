namespace Vefa.CustomAuth.Core.Stores;

/// <summary>
/// Represents the user information returned by the host application's user store.
/// </summary>
public sealed class CustomAuthUserInfo
{
    /// <summary>
    /// Gets or sets the stable user identifier used as the subject claim.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the optional display or login name.
    /// </summary>
    public string? UserName { get; set; }

    /// <summary>
    /// Gets or sets the optional email address.
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// Gets or sets optional additional claims to include in issued tokens and userinfo responses.
    /// </summary>
    public IReadOnlyDictionary<string, string>? AdditionalClaims { get; set; }
}
