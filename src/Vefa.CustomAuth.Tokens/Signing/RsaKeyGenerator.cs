using System.Security.Cryptography;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Tokens.Signing;

/// <summary>
/// Generates a new RSA signing key and returns it as a <see cref="CustomAuthSigningKey"/>.
/// The private key is stored as PKCS#8 PEM, the public key as SubjectPublicKeyInfo PEM.
/// </summary>
public static class RsaKeyGenerator
{
    /// <summary>
    /// The default RSA signing algorithm.
    /// </summary>
    public const string DefaultAlgorithm = "RS256";
    private const int KeySize = 2048;

    /// <summary>
    /// Generates a new RSA signing key.
    /// </summary>
    /// <param name="now">The key creation timestamp.</param>
    /// <returns>The generated signing key.</returns>
    public static CustomAuthSigningKey Generate(DateTimeOffset now)
    {
        using var rsa = RSA.Create(KeySize);

        return new CustomAuthSigningKey
        {
            KeyId = Guid.NewGuid().ToString("N"),
            Algorithm = DefaultAlgorithm,
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
            PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
            CreatedAt = now,
            IsActive = true,
        };
    }

    /// <summary>
    /// Imports the private RSA key material from a stored signing key.
    /// </summary>
    /// <param name="key">The signing key containing private key material.</param>
    /// <returns>The imported RSA key.</returns>
    public static RSA ImportPrivateKey(CustomAuthSigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var rsa = RSA.Create();
        rsa.ImportFromPem(key.PrivateKeyPem);
        return rsa;
    }

    /// <summary>
    /// Imports the public RSA key material from a stored signing key.
    /// </summary>
    /// <param name="key">The signing key containing public key material.</param>
    /// <returns>The imported RSA key.</returns>
    public static RSA ImportPublicKey(CustomAuthSigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var rsa = RSA.Create();
        rsa.ImportFromPem(key.PublicKeyPem);
        return rsa;
    }
}
