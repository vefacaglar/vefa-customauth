namespace Vefa.CustomAuth.Core.Models;

public sealed class CustomAuthSigningKey
{
    public string KeyId { get; set; } = default!;
    public string Algorithm { get; set; } = "RS256";
    public string PrivateKeyPem { get; set; } = default!;
    public string PublicKeyPem { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }
    public bool IsActive { get; set; }
}
