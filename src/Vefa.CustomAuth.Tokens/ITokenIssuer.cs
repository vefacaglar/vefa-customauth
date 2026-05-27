namespace Vefa.CustomAuth.Tokens;

public sealed class TokenIssueRequest
{
    public string Subject { get; set; } = default!;
    public string ClientId { get; set; } = default!;
    public string Scope { get; set; } = default!;
    public DateTimeOffset? AuthTime { get; set; }
    public IReadOnlyDictionary<string, string>? AdditionalClaims { get; set; }
}

public sealed class IssuedTokens
{
    public string AccessToken { get; set; } = default!;
    public string IdToken { get; set; } = default!;
    public string RefreshToken { get; set; } = default!;
    public int AccessTokenExpiresInSeconds { get; set; }
}

public interface ITokenIssuer
{
    Task<IssuedTokens> IssueAsync(TokenIssueRequest request, CancellationToken cancellationToken = default);
}
