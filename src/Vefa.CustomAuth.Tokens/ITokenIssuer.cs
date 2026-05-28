namespace Vefa.CustomAuth.Tokens;

/// <summary>
/// Represents the inputs required to issue tokens for an authenticated user and client.
/// </summary>
public sealed class TokenIssueRequest
{
    /// <summary>
    /// Gets or sets the subject identifier for the authenticated user.
    /// </summary>
    public string Subject { get; set; } = default!;

    /// <summary>
    /// Gets or sets the client identifier that requested the tokens.
    /// </summary>
    public string ClientId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the space-delimited granted scopes.
    /// </summary>
    public string Scope { get; set; } = default!;

    /// <summary>
    /// Gets or sets the time when the user authenticated, when available.
    /// </summary>
    public DateTimeOffset? AuthTime { get; set; }

    /// <summary>
    /// Gets or sets optional additional claims to include in user-facing tokens.
    /// </summary>
    public IReadOnlyDictionary<string, string>? AdditionalClaims { get; set; }
}

/// <summary>
/// Represents tokens issued by the authorization server.
/// </summary>
public sealed class IssuedTokens
{
    /// <summary>
    /// Gets or sets the JWT access token.
    /// </summary>
    public string AccessToken { get; set; } = default!;

    /// <summary>
    /// Gets or sets the JWT ID token.
    /// </summary>
    public string IdToken { get; set; } = default!;

    /// <summary>
    /// Gets or sets the opaque refresh token.
    /// </summary>
    public string RefreshToken { get; set; } = default!;

    /// <summary>
    /// Gets or sets the access token lifetime in seconds.
    /// </summary>
    public int AccessTokenExpiresInSeconds { get; set; }
}

/// <summary>
/// Issues access, ID, and refresh tokens.
/// </summary>
public interface ITokenIssuer
{
    /// <summary>
    /// Issues tokens for the supplied request.
    /// </summary>
    /// <param name="request">The token issue request.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The issued token set.</returns>
    Task<IssuedTokens> IssueAsync(TokenIssueRequest request, CancellationToken cancellationToken = default);
}
