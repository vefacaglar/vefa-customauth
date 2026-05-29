using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Vefa.CustomAuth.AspNetCore.Endpoints.Grants;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// Dispatches token-endpoint requests to the registered <see cref="ICustomAuthGrantHandler"/> whose
/// <see cref="ICustomAuthGrantHandler.GrantType"/> matches the request's <c>grant_type</c>.
/// A handler registered for an existing grant type overrides the built-in one (last registration wins).
/// </summary>
internal sealed partial class TokenEndpointService
{
    private readonly Dictionary<string, ICustomAuthGrantHandler> _handlers;
    private readonly ILogger<TokenEndpointService> _logger;

    public TokenEndpointService(
        IEnumerable<ICustomAuthGrantHandler> handlers,
        ILogger<TokenEndpointService> logger)
    {
        ArgumentNullException.ThrowIfNull(handlers);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _handlers = new Dictionary<string, ICustomAuthGrantHandler>(StringComparer.Ordinal);
        foreach (var handler in handlers)
        {
            // Last registration wins, so a host can override a built-in grant by registering its own.
            _handlers[handler.GrantType] = handler;
        }
    }

    public async Task<IResult> HandleAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.HasFormContentType)
        {
            return EndpointResults.OAuthError("invalid_request", "Token requests must use application/x-www-form-urlencoded.");
        }

        var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
        var grantType = form["grant_type"].ToString();

        if (string.IsNullOrEmpty(grantType) || !_handlers.TryGetValue(grantType, out var handler))
        {
            LogUnsupportedGrantType(string.IsNullOrEmpty(grantType) ? "(none)" : grantType);
            return EndpointResults.OAuthError("unsupported_grant_type", "The grant type is not supported.");
        }

        return await handler.HandleAsync(form, cancellationToken).ConfigureAwait(false);
    }

    [LoggerMessage(EventId = 2000, Level = LogLevel.Warning,
        Message = "Token request rejected: unsupported grant_type '{GrantType}'.")]
    private partial void LogUnsupportedGrantType(string grantType);
}
