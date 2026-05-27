using Microsoft.AspNetCore.Http;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class RevocationEndpointService
{
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly TimeProvider _timeProvider;

    public RevocationEndpointService(
        ICustomAuthTokenManager tokenManager,
        TimeProvider timeProvider)
    {
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<IResult> HandleAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Revocation endpoint MUST be requested via POST in form urlencoded
        if (!string.Equals(request.Method, HttpMethods.Post, StringComparison.OrdinalIgnoreCase))
        {
            return EndpointResults.OAuthError("invalid_request", "Revocation requests must use POST method.", StatusCodes.Status405MethodNotAllowed);
        }

        if (!request.HasFormContentType)
        {
            return EndpointResults.OAuthError("invalid_request", "Content-Type must be 'application/x-www-form-urlencoded'.");
        }

        var token = request.Form["token"].ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return EndpointResults.OAuthError("invalid_request", "The token parameter is required.");
        }

        // We only support revoking refresh tokens in v0.2.
        // Hashing the token because we store refresh tokens as hashes.
        var tokenHash = TokenHasher.Hash(token);
        var storedToken = await _tokenManager.FindRefreshTokenByHashAsync(tokenHash, cancellationToken).ConfigureAwait(false);

        if (storedToken is not null && storedToken.RevokedAt is null)
        {
            var now = _timeProvider.GetUtcNow();
            await _tokenManager.RevokeRefreshTokenAsync(storedToken.Id, now, cancellationToken).ConfigureAwait(false);
        }

        // RFC 7009: The server MUST return 200 OK whether the token was active or invalid.
        return Results.Ok();
    }
}
