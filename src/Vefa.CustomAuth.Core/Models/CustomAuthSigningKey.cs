namespace Vefa.CustomAuth.Core.Models;

/// <summary>
/// Represents a cryptographic signing key used to sign JWT access and ID tokens.
/// Private key material remains securely on the server and is never exposed.
/// </summary>
public sealed class CustomAuthSigningKey
{
    /// <summary>
    /// Gets or sets the unique identifier (kid) of the signing key.
    /// </summary>
    public string KeyId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the cryptographic algorithm used for signing (defaults to "RS256").
    /// </summary>
    public string Algorithm { get; set; } = "RS256";

    /// <summary>
    /// Gets or sets the PEM-encoded private key material.
    /// </summary>
    public string PrivateKeyPem { get; set; } = default!;

    /// <summary>
    /// Gets or sets the PEM-encoded public key material.
    /// Used by resource servers and clients to verify issued tokens.
    /// </summary>
    public string PublicKeyPem { get; set; } = default!;

    /// <summary>
    /// Gets or sets the creation date and time of the signing key.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the signing key was retired (deactivated).
    /// </summary>
    public DateTimeOffset? RetiredAt { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this key is currently active and used for signing new tokens.
    /// </summary>
    public bool IsActive { get; set; }
}
