namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Identifies how a client authenticates itself to the token endpoint
/// (OpenID Connect Core 1.0 §9, <c>token_endpoint_auth_method</c>).
/// </summary>
public enum CustomAuthClientAuthenticationMethod
{
    /// <summary>
    /// The client is a public client and does not authenticate at the token endpoint.
    /// Security relies on PKCE. This is the default.
    /// </summary>
    None = 0,

    /// <summary>
    /// The client authenticates with a JWT assertion signed by its private key
    /// (<c>private_key_jwt</c>, RFC 7521 / 7523). The authorization server verifies the
    /// signature with the client's registered public key. The private key never leaves the client.
    /// </summary>
    PrivateKeyJwt = 1,
}
