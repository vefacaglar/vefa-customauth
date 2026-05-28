using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal static class PkceVerifier
{
    public static bool IsSupportedMethod(string? method)
        => string.Equals(method, "S256", StringComparison.Ordinal);

    public static bool Verify(string verifier, string challenge, string method)
    {
        ArgumentException.ThrowIfNullOrEmpty(verifier);
        ArgumentException.ThrowIfNullOrEmpty(challenge);
        ArgumentException.ThrowIfNullOrEmpty(method);

        if (!string.Equals(method, "S256", StringComparison.Ordinal))
        {
            return false;
        }

        var expected = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return SecureCompare.FixedTimeEquals(expected, challenge);
    }
}
