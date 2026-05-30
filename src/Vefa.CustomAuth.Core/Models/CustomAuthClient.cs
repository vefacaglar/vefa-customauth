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
    /// Gets the relational redirect URI records for persistence providers that model client URIs as child rows.
    /// </summary>
    public List<CustomAuthClientRedirectUri> RedirectUriEntries { get; } = new();

    /// <summary>
    /// Gets or sets the list of allowed post-logout redirect URIs after the user ends their session.
    /// </summary>
    public List<string> PostLogoutRedirectUris { get; set; } = new();

    /// <summary>
    /// Gets the relational post-logout redirect URI records for persistence providers that model client URIs as child rows.
    /// </summary>
    public List<CustomAuthClientPostLogoutRedirectUri> PostLogoutRedirectUriEntries { get; } = new();

    /// <summary>
    /// Gets or sets the list of scopes that this client is permitted to request.
    /// </summary>
    public List<string> AllowedScopes { get; set; } = new();

    /// <summary>
    /// Gets the relational allowed-scope records for persistence providers that model client scopes as child rows.
    /// </summary>
    public List<CustomAuthClientAllowedScope> AllowedScopeEntries { get; } = new();

    /// <summary>
    /// Gets or sets a value indicating whether this client is required to use Proof Key for Code Exchange (PKCE).
    /// </summary>
    public bool RequirePkce { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether this client is allowed to request refresh tokens for long-lived offline access.
    /// </summary>
    public bool AllowRefreshTokens { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether this client may use the OAuth2 client credentials
    /// grant (RFC 6749 §4.4) to obtain access tokens on its own behalf. Requires a confidential
    /// authentication method (not <see cref="CustomAuthClientAuthenticationMethod.None"/>).
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool AllowClientCredentials { get; set; }

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

    /// <summary>
    /// Gets or sets how the client authenticates at the token endpoint. Defaults to
    /// <see cref="CustomAuthClientAuthenticationMethod.None"/> (public client, PKCE only).
    /// </summary>
    public CustomAuthClientAuthenticationMethod TokenEndpointAuthMethod { get; set; }
        = CustomAuthClientAuthenticationMethod.None;

    /// <summary>
    /// Gets or sets the client's public keys as a JSON Web Key Set (JWKS) document, used to verify
    /// <c>private_key_jwt</c> client assertions. Required when
    /// <see cref="TokenEndpointAuthMethod"/> is <see cref="CustomAuthClientAuthenticationMethod.PrivateKeyJwt"/>.
    /// This holds public key material only; private keys never leave the client.
    /// </summary>
    public string? JwksJson { get; set; }

    /// <summary>
    /// Gets or sets a free-form bag of additional string properties associated with the client.
    /// This is a forward-compatibility extension point: features that need extra per-client
    /// configuration (for example resource/audience values, custom claim mappings, or feature
    /// flags) can store it here without requiring a relational schema change. Relational providers
    /// persist this as a single JSON column. Never store secrets or private key material here.
    /// </summary>
    public IDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
}
