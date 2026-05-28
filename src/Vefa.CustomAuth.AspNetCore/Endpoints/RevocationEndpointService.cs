using Microsoft.AspNetCore.Http;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class RevocationEndpointService
{
    private readonly ICustomAuthClientManager _clientManager;
    private readonly ICustomAuthTokenManager _tokenManager;
    private readonly TimeProvider _timeProvider;

    public RevocationEndpointService(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        TimeProvider timeProvider)
    {
        _clientManager = clientManager ?? throw new ArgumentNullException(nameof(clientManager));
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

        var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var token = form["token"].ToString();
        var clientId = form["client_id"].ToString();
        var tokenTypeHint = form["token_type_hint"].ToString();

        if (string.IsNullOrWhiteSpace(token))
        {
            return EndpointResults.OAuthError("invalid_request", "The token parameter is required.");
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return EndpointResults.OAuthError("invalid_request", "The client_id parameter is required.");
        }

        var client = await _clientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            return EndpointResults.OAuthError("invalid_client", "The client is not registered.", StatusCodes.Status401Unauthorized);
        }

        // Hashing the token because we store refresh tokens as hashes.
        var tokenHash = TokenHasher.Hash(token);
        var storedToken = await _tokenManager.FindRefreshTokenByHashAsync(tokenHash, cancellationToken).ConfigureAwait(false);

        if (storedToken is not null)
        {
            if (!string.Equals(storedToken.ClientId, clientId, StringComparison.Ordinal))
            {
                // RFC 7009: "If the client is not authorized to revoke the token... return invalid_grant"
                return EndpointResults.OAuthError("invalid_grant", "The client is not authorized to revoke this token.");
            }

            if (storedToken.RevokedAt is null)
            {
                var now = _timeProvider.GetUtcNow();
                await _tokenManager.RevokeRefreshTokenChainAsync(storedToken, now, cancellationToken).ConfigureAwait(false);
            }
        }

        // RFC 7009: The server MUST return 200 OK whether the token was active or invalid.
        return Results.Ok();
    }
}
