namespace Vefa.CustomAuth.Core.Models;

public sealed class CustomAuthSession
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
