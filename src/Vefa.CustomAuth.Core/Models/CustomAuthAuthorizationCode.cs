namespace Vefa.CustomAuth.Core.Models;

public sealed class CustomAuthAuthorizationCode
{
    public Guid Id { get; set; }
    public string CodeHash { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string UserId { get; set; } = default!;
    public string RedirectUri { get; set; } = default!;
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string Scope { get; set; } = default!;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
