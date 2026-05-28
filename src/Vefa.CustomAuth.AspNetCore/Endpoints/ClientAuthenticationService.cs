using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Services;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.ClientAssertion;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// Authenticates the client at the token endpoint according to its
/// <see cref="CustomAuthClient.TokenEndpointAuthMethod"/>. Public clients (<c>None</c>) pass through
/// unchanged; <c>private_key_jwt</c> clients must present a valid, non-replayed signed assertion.
/// </summary>
internal sealed partial class ClientAuthenticationService
{
    internal const string JwtBearerClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static readonly IDictionary<string, string> UnauthorizedHeaders = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["WWW-Authenticate"] = "Basic realm=\"Vefa.CustomAuth\"",
    };

    private readonly IClientAssertionValidator _assertionValidator;
    private readonly IClientAssertionReplayCache _replayCache;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly ILogger<ClientAuthenticationService> _logger;

    public ClientAuthenticationService(
        IClientAssertionValidator assertionValidator,
        IClientAssertionReplayCache replayCache,
        IOptionsMonitor<CustomAuthOptions> options,
        ILogger<ClientAuthenticationService> logger)
    {
        _assertionValidator = assertionValidator ?? throw new ArgumentNullException(nameof(assertionValidator));
        _replayCache = replayCache ?? throw new ArgumentNullException(nameof(replayCache));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Authenticates the client for a token request. Returns <c>null</c> when authentication
    /// succeeds (or is not required), or an <see cref="IResult"/> error to return to the caller.
    /// </summary>
    public async Task<IResult?> AuthenticateAsync(CustomAuthClient client, IFormCollection form, CancellationToken cancellationToken)
    {
        if (client.TokenEndpointAuthMethod == CustomAuthClientAuthenticationMethod.None)
        {
            return null;
        }

        // CustomAuthClientAuthenticationMethod.PrivateKeyJwt
        var assertionType = form["client_assertion_type"].ToString();
        var assertion = form["client_assertion"].ToString();

        if (!string.Equals(assertionType, JwtBearerClientAssertionType, StringComparison.Ordinal))
        {
            LogMissingAssertionType(client.ClientId, string.IsNullOrEmpty(assertionType) ? "(none)" : assertionType);
            return InvalidClient();
        }

        if (string.IsNullOrWhiteSpace(assertion))
        {
            LogMissingAssertion(client.ClientId);
            return InvalidClient();
        }

        if (string.IsNullOrWhiteSpace(client.JwksJson))
        {
            LogClientMisconfigured(client.ClientId);
            return InvalidClient();
        }

        var result = await _assertionValidator.ValidateAsync(
            assertion,
            client.JwksJson,
            client.ClientId,
            GetValidAudiences(),
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            LogAssertionInvalid(client.ClientId, result.FailureReason ?? "invalid");
            return InvalidClient();
        }

        var registered = await _replayCache.TryRegisterAsync(
            client.ClientId,
            result.Jti!,
            result.ExpiresAt!.Value,
            cancellationToken).ConfigureAwait(false);

        if (!registered)
        {
            LogAssertionReplay(client.ClientId, result.Jti!);
            return InvalidClient();
        }

        LogClientAuthenticated(client.ClientId);
        return null;
    }

    private string[] GetValidAudiences()
    {
        var issuer = _options.CurrentValue.Issuer.TrimEnd('/');
        return new[] { issuer, $"{issuer}/connect/token" };
    }

    private static IResult InvalidClient()
        => EndpointResults.OAuthError(
            "invalid_client",
            "Client authentication failed.",
            StatusCodes.Status401Unauthorized,
            UnauthorizedHeaders);

    // Client authentication diagnostics. Event IDs 2050-2099. The raw assertion is never logged.

    [LoggerMessage(EventId = 2050, Level = LogLevel.Warning,
        Message = "Client authentication failed (invalid_client): client '{ClientId}' requires private_key_jwt but client_assertion_type was '{AssertionType}'.")]
    private partial void LogMissingAssertionType(string clientId, string assertionType);

    [LoggerMessage(EventId = 2051, Level = LogLevel.Warning,
        Message = "Client authentication failed (invalid_client): client '{ClientId}' requires private_key_jwt but no client_assertion was supplied.")]
    private partial void LogMissingAssertion(string clientId);

    [LoggerMessage(EventId = 2052, Level = LogLevel.Error,
        Message = "Client authentication failed (invalid_client): client '{ClientId}' is configured for private_key_jwt but has no registered JWKS.")]
    private partial void LogClientMisconfigured(string clientId);

    [LoggerMessage(EventId = 2053, Level = LogLevel.Warning,
        Message = "Client authentication failed (invalid_client): assertion for client '{ClientId}' is invalid: {Reason}")]
    private partial void LogAssertionInvalid(string clientId, string reason);

    [LoggerMessage(EventId = 2054, Level = LogLevel.Warning,
        Message = "Client authentication failed (invalid_client): replayed client assertion for client '{ClientId}' (jti: {Jti}).")]
    private partial void LogAssertionReplay(string clientId, string jti);

    [LoggerMessage(EventId = 2055, Level = LogLevel.Information,
        Message = "Client '{ClientId}' authenticated via private_key_jwt.")]
    private partial void LogClientAuthenticated(string clientId);
}
