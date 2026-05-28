using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Vefa.CustomAuth.Tokens;

/// <summary>
/// SHA-256 + base64url helper for storing opaque tokens
/// (authorization codes, refresh tokens) as hashes in persistence.
/// </summary>
public static class TokenHasher
{
    /// <summary>
    /// Hashes an opaque token using SHA-256 and base64url encoding.
    /// </summary>
    /// <param name="token">The raw token value.</param>
    /// <returns>The token hash.</returns>
    public static string Hash(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Base64UrlEncoder.Encode(bytes);
    }

    /// <summary>
    /// Creates a cryptographically random opaque token.
    /// </summary>
    /// <param name="byteLength">The random byte length. Must be at least 16 bytes.</param>
    /// <returns>The base64url-encoded opaque token.</returns>
    public static string CreateOpaqueToken(int byteLength = 32)
    {
        if (byteLength < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), "Token length must be at least 16 bytes.");
        }

        var buffer = new byte[byteLength];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncoder.Encode(buffer);
    }
}
