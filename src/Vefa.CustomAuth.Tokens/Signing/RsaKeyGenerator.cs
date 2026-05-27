using System.Security.Cryptography;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.Tokens.Signing;

/// <summary>
/// Generates a new RSA signing key and returns it as a <see cref="CustomAuthSigningKey"/>.
/// The private key is stored as PKCS#8 PEM, the public key as SubjectPublicKeyInfo PEM.
/// </summary>
public static class RsaKeyGenerator
{
    public const string DefaultAlgorithm = "RS256";
    private const int KeySize = 2048;

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

    public static RSA ImportPrivateKey(CustomAuthSigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var rsa = RSA.Create();
        rsa.ImportFromPem(key.PrivateKeyPem);
        return rsa;
    }

    public static RSA ImportPublicKey(CustomAuthSigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var rsa = RSA.Create();
        rsa.ImportFromPem(key.PublicKeyPem);
        return rsa;
    }
}
