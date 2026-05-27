namespace Vefa.CustomAuth.Core.Models;

public sealed class CustomAuthRefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string UserId { get; set; } = default!;
    public Guid? SessionId { get; set; }
    public string Scope { get; set; } = default!;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
