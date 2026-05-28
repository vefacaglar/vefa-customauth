namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents an OAuth2 / OpenID Connect client application registered with the authorization server.
/// </summary>
public sealed class CustomAuthClient
{
    /// <summary>
    /// Gets or sets the unique identifier for the client application.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the display name of the client application.
    /// </summary>
    public string DisplayName { get; set; } = default!;

    /// <summary>
    /// Gets or sets the list of allowed redirect URIs that the client can request authorization codes to be sent to.
    /// </summary>
    public List<string> RedirectUris { get; set; } = new();

    /// <summary>
    /// Gets or sets the list of allowed post-logout redirect URIs after the user ends their session.
    /// </summary>
    public List<string> PostLogoutRedirectUris { get; set; } = new();

    /// <summary>
    /// Gets or sets the list of scopes that this client is permitted to request.
    /// </summary>
    public List<string> AllowedScopes { get; set; } = new();

    /// <summary>
    /// Gets or sets a value indicating whether this client is required to use Proof Key for Code Exchange (PKCE).
    /// </summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether this client is allowed to request refresh tokens for long-lived offline access.
    /// </summary>
    public bool AllowRefreshTokens { get; set; } = true;

    /// <summary>
    /// Gets or sets the lifetime of issued access tokens in seconds. Defaults to 3600 (1 hour).
    /// </summary>
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;

    /// <summary>
    /// Gets or sets the lifetime of issued refresh tokens in seconds. Defaults to 2592000 (30 days).
    /// </summary>
    public int RefreshTokenLifetimeSeconds { get; set; } = 2592000;

    /// <summary>
    /// Gets or sets the absolute lifetime of a refresh token chain in seconds. Defaults to 2592000 (30 days).
    /// Rotation must not extend a refresh token chain beyond this lifetime.
    /// </summary>
    public int RefreshTokenAbsoluteLifetimeSeconds { get; set; } = 2592000;
}
