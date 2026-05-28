namespace Vefa.CustomAuth.AspNetCore.Client;

/// <summary>
/// Configures the OIDC client integration installed by
/// <see cref="CustomAuthClientExtensions.AddCustomAuthClient"/>. Properties not
/// touched here keep their library defaults (PKCE on, response_type=code, refresh
/// tokens saved, <c>name</c> claim mapping, etc.).
/// </summary>
public sealed class CustomAuthClientOptions
{
    /// <summary>
    /// Gets or sets the issuer URI of the Vefa.CustomAuth authorization server
    /// (e.g. <c>https://auth.example.com</c>). Required.
    /// </summary>
    public string Authority { get; set; } = default!;

    /// <summary>
    /// Gets or sets the registered <c>client_id</c> for this application. Required.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the optional client secret. Leave empty for public clients (PKCE-only).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether discovery and JWKS metadata must be
    /// served over HTTPS. Defaults to <c>true</c>; set to <c>false</c> only for local
    /// development against an HTTP issuer.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Gets or sets the relative path the authorization server redirects back to
    /// after a successful sign-in. Defaults to <c>/signin-oidc</c>.
    /// </summary>
    public string CallbackPath { get; set; } = "/signin-oidc";

    /// <summary>
    /// Gets or sets the relative path the authorization server redirects back to
    /// after a successful sign-out. Defaults to <c>/signout-callback-oidc</c>.
    /// </summary>
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";

    /// <summary>
    /// Gets or sets the relative path the application redirects to after the local
    /// cookie sign-out completes. Defaults to <c>/</c>.
    /// </summary>
    public string SignedOutRedirectUri { get; set; } = "/";

    /// <summary>
    /// Gets the base scope list requested at sign-in. Pre-populated with
    /// <c>openid profile email offline_access</c>; clear it to start from scratch.
    /// </summary>
    public IList<string> Scopes { get; } = new List<string> { "openid", "profile", "email", "offline_access" };

    /// <summary>
    /// Gets the list of additional scopes appended to <see cref="Scopes"/> (e.g. API
    /// audience scopes like <c>orders-api</c>). Defaults to empty.
    /// </summary>
    public IList<string> AdditionalScopes { get; } = new List<string>();

    /// <summary>
    /// Gets or sets a value indicating whether tokens should be persisted in the
    /// authentication cookie so the application can call APIs on the user's behalf.
    /// Defaults to <c>true</c>.
    /// </summary>
    public bool SaveTokens { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether to call the userinfo endpoint to
    /// supplement the claims principal. Defaults to <c>false</c> — the ID token
    /// usually carries everything needed.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether <c>nonce</c> validation is enforced
    /// on the ID token. Defaults to <c>true</c>; only flip this off for back-channel
    /// integration tests where nonce cannot be persisted.
    /// </summary>
    public bool RequireNonce { get; set; } = true;
}
