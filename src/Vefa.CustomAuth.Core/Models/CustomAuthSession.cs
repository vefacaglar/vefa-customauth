namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents an authenticated Single Sign-On (SSO) session for a user on the authorization server.
/// </summary>
public sealed class CustomAuthSession
{
    /// <summary>
    /// Gets or sets the unique identifier of the session.
    /// This value is stored in the browser's session cookie.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Gets or sets the unique identifier of the authenticated user.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the creation date and time of the session.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the expiration date and time of the session.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the session was actively ended (revoked).
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
}
