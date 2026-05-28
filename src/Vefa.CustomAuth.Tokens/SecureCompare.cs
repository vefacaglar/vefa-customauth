using System.Security.Cryptography;
using System.Text;

namespace Vefa.CustomAuth.Tokens;

/// <summary>
/// Provides timing-attack resistant comparison of cryptographic values.
/// </summary>
public static class SecureCompare
{
    /// <summary>
    /// Performs a constant-time comparison of two string values using UTF-8 representation.
    /// </summary>
    /// <param name="a">The first string to compare.</param>
    /// <param name="b">The second string to compare.</param>
    /// <returns>True if the strings are equal; otherwise, false.</returns>
    public static bool FixedTimeEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return a is null && b is null;
        }

        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);

        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }
}
