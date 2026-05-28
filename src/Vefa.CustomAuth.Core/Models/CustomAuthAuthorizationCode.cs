namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a short-lived authorization code used in the OAuth2 Authorization Code Flow.
/// </summary>
public sealed class CustomAuthAuthorizationCode
{
    /// <summary>
    /// Gets or sets the primary key for the authorization code.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Gets or sets the cryptographically secure hash of the raw opaque authorization code.
    /// Only the hashed code is stored in the persistence layer.
    /// </summary>
    public string CodeHash { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the client application that requested the code.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the authenticated user who authorized the client.
    /// </summary>
    public string UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique identifier of the SSO session that issued this authorization code.
    /// </summary>
    public Guid? SessionId { get; set; }

    /// <summary>
    /// Gets or sets the redirect URI provided in the initial authorization request.
    /// Must exactly match the redirect URI supplied during token exchange.
    /// </summary>
    public string RedirectUri { get; set; } = default!;

    /// <summary>
    /// Gets or sets the PKCE code challenge.
    /// </summary>
    public string? CodeChallenge { get; set; }

    /// <summary>
    /// Gets or sets the PKCE code challenge method (typically S256 or plain).
    /// </summary>
    public string? CodeChallengeMethod { get; set; }

    /// <summary>
    /// Gets or sets the list of space-delimited scopes requested and approved in the authorization request.
    /// </summary>
    public string Scope { get; set; } = default!;

    /// <summary>
    /// Gets or sets the exact date and time when the authorization code will expire.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the code was exchanged for tokens.
    /// Codes are single-use; any code with a non-null ConsumedAt value must be rejected.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>
    /// Gets or sets the creation date and time of the authorization code.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }
}
