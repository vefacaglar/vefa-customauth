using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens;

namespace Vefa.CustomAuth.AspNetCore.Endpoints.Grants;

/// <summary>
/// Handles the <c>client_credentials</c> grant (RFC 6749 §4.4): a confidential client authenticates
/// with its own credentials and receives an access token representing itself. No end user is
/// involved, so no ID token or refresh token is issued and the access token's <c>sub</c> is the
/// client identifier.
/// </summary>
internal sealed partial class ClientCredentialsGrantHandler : GrantHandlerBase
{
    private readonly ILogger<ClientCredentialsGrantHandler> _logger;

    public ClientCredentialsGrantHandler(
        ICustomAuthClientManager clientManager,
        ICustomAuthTokenManager tokenManager,
        ITokenIssuer tokenIssuer,
        ClientAuthenticationService clientAuthentication,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider,
        ILogger<ClientCredentialsGrantHandler> logger)
        : base(clientManager, tokenManager, tokenIssuer, clientAuthentication, options, timeProvider)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public override string GrantType => "client_credentials";

    public override async Task<IResult> HandleAsync(IFormCollection form, CancellationToken cancellationToken = default)
    {
        var clientId = form["client_id"].ToString();
        if (string.IsNullOrWhiteSpace(clientId))
        {
            LogMissingClientId();
            return EndpointResults.OAuthError("invalid_request", "client_id is required.");
        }

        var client = await ClientManager.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
        {
            LogUnknownClient(clientId);
            return UnknownClient();
        }

        // The client credentials grant requires a confidential client. ClientAuthenticationService
        // passes 'None' clients through without authenticating, so reject them explicitly here.
        if (client.TokenEndpointAuthMethod == CustomAuthClientAuthenticationMethod.None)
        {
            LogPublicClientRejected(clientId);
            return UnknownClient();
        }

        var authError = await ClientAuthentication.AuthenticateAsync(client, form, cancellationToken).ConfigureAwait(false);
        if (authError is not null)
        {
            return authError;
        }

        if (!client.AllowClientCredentials)
        {
            LogGrantNotEnabled(clientId);
            return EndpointResults.OAuthError("unauthorized_client", "The client is not authorized to use the client credentials grant.");
        }

        var scope = form["scope"].ToString();
        if (!IsScopeAllowed(client, scope))
        {
            LogInvalidScope(clientId, scope);
            return EndpointResults.OAuthError("invalid_scope", "One or more requested scopes are not allowed for this client.");
        }

        var issued = await TokenIssuer.IssueClientCredentialsTokenAsync(
            new TokenIssueRequest
            {
                Subject = client.ClientId,
                ClientId = client.ClientId,
                Scope = scope,
            },
            cancellationToken).ConfigureAwait(false);

        LogExchangeSucceeded(clientId, scope);
        return EndpointResults.NoStoreJson(CreateResponse(issued, scope));
    }

    private static object CreateResponse(IssuedClientCredentialsToken issued, string scope)
    {
        var response = new Dictionary<string, object?>
        {
            ["access_token"] = issued.AccessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = issued.AccessTokenExpiresInSeconds,
        };

        if (!string.IsNullOrWhiteSpace(scope))
        {
            response["scope"] = scope;
        }

        return response;
    }

    // Client credentials diagnostics. Event IDs 2060-2069. Tokens are never logged.

    [LoggerMessage(EventId = 2060, Level = LogLevel.Warning,
        Message = "Client credentials exchange rejected (invalid_request): client_id is required.")]
    private partial void LogMissingClientId();

    [LoggerMessage(EventId = 2061, Level = LogLevel.Warning,
        Message = "Client credentials exchange rejected (invalid_client): client '{ClientId}' is not registered.")]
    private partial void LogUnknownClient(string clientId);

    [LoggerMessage(EventId = 2062, Level = LogLevel.Warning,
        Message = "Client credentials exchange rejected (invalid_client): client '{ClientId}' is a public client (token_endpoint_auth_method 'none') and cannot use the client credentials grant.")]
    private partial void LogPublicClientRejected(string clientId);

    [LoggerMessage(EventId = 2063, Level = LogLevel.Warning,
        Message = "Client credentials exchange rejected (unauthorized_client): client '{ClientId}' is not enabled for the client credentials grant (AllowClientCredentials is false).")]
    private partial void LogGrantNotEnabled(string clientId);

    [LoggerMessage(EventId = 2064, Level = LogLevel.Warning,
        Message = "Client credentials exchange rejected (invalid_scope): one or more requested scopes '{Scope}' are not in the client's allowed scopes (client: {ClientId}).")]
    private partial void LogInvalidScope(string clientId, string scope);

    [LoggerMessage(EventId = 2065, Level = LogLevel.Information,
        Message = "Client credentials exchange succeeded (client: {ClientId}, scope: '{Scope}').")]
    private partial void LogExchangeSucceeded(string clientId, string scope);
}
