namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a long-lived, opaque refresh token used to request new access tokens.
/// </summary>
public sealed class CustomAuthRefreshToken
{
    /// <summary>
    /// Gets or sets the primary key for the refresh token.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Gets or sets the cryptographically secure hash of the raw opaque refresh token.
    /// Only the hashed token is stored in the database.
    /// </summary>
    public string TokenHash { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the client application that requested the token.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the user associated with this refresh token.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the SSO session associated with this refresh token.
    /// </summary>
    public Guid? SessionId { get; set; }

    /// <summary>
    /// Gets or sets the scopes granted to this refresh token.
    /// </summary>
    public string Scope { get; set; } = default!;

    /// <summary>
    /// Gets or sets the exact date and time when the refresh token will expire.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the refresh token was rotated (consumed).
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the refresh token was actively revoked.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// Gets or sets the creation date and time of the refresh token.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }
}
