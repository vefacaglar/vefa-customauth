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
    public static string Hash(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Base64UrlEncoder.Encode(bytes);
    }

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
