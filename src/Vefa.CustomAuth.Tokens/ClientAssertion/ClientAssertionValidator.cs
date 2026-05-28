using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.Tokens.ClientAssertion;

/// <summary>
/// Default <see cref="IClientAssertionValidator"/> backed by <see cref="JsonWebTokenHandler"/>.
/// Only asymmetric signing algorithms are accepted; <c>none</c> and symmetric (HMAC) algorithms
/// are rejected so a leaked or absent key cannot be used to forge an assertion.
/// </summary>
public sealed class ClientAssertionValidator : IClientAssertionValidator
{
    // Asymmetric algorithms only. HMAC ("HS*") and "none" are intentionally excluded.
    private static readonly string[] AllowedAlgorithms =
    {
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
    };

    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly JsonWebTokenHandler _handler = new();

    public ClientAssertionValidator(IOptionsMonitor<CustomAuthOptions> options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<ClientAssertionValidationResult> ValidateAsync(
        string assertion,
        string jwksJson,
        string? expectedClientId,
        IReadOnlyCollection<string> validAudiences,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(assertion))
        {
            return ClientAssertionValidationResult.Failure("client_assertion is missing.");
        }

        if (string.IsNullOrWhiteSpace(jwksJson))
        {
            return ClientAssertionValidationResult.Failure("the client has no registered JWKS to verify the assertion.");
        }

        if (validAudiences is null || validAudiences.Count == 0)
        {
            return ClientAssertionValidationResult.Failure("no expected audiences were supplied.");
        }

        IList<SecurityKey> signingKeys;
        try
        {
            signingKeys = new JsonWebKeySet(jwksJson).GetSigningKeys();
        }
        catch (Exception ex)
        {
            return ClientAssertionValidationResult.Failure($"the client JWKS could not be parsed: {ex.GetType().Name}.");
        }

        if (signingKeys.Count == 0)
        {
            return ClientAssertionValidationResult.Failure("the client JWKS contains no usable signing keys.");
        }

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            RequireSignedTokens = true,
            ValidAlgorithms = AllowedAlgorithms,

            // Issuer is verified manually below so we can also enforce iss == sub == client_id.
            ValidateIssuer = false,

            ValidateAudience = true,
            ValidAudiences = validAudiences,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = _options.CurrentValue.ClientAssertionClockSkew,
        };

        var result = await _handler.ValidateTokenAsync(assertion, parameters).ConfigureAwait(false);
        if (!result.IsValid)
        {
            return ClientAssertionValidationResult.Failure(
                $"assertion signature or claim validation failed: {result.Exception?.GetType().Name ?? "invalid"}.");
        }

        if (result.SecurityToken is not JsonWebToken jwt)
        {
            return ClientAssertionValidationResult.Failure("the assertion is not a JWT.");
        }

        var issuer = jwt.Issuer;
        var subject = jwt.Subject;

        if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(subject))
        {
            return ClientAssertionValidationResult.Failure("the assertion is missing iss or sub.");
        }

        if (!string.Equals(issuer, subject, StringComparison.Ordinal))
        {
            return ClientAssertionValidationResult.Failure("the assertion iss and sub do not match.");
        }

        if (expectedClientId is not null && !string.Equals(issuer, expectedClientId, StringComparison.Ordinal))
        {
            return ClientAssertionValidationResult.Failure("the assertion iss/sub does not match the expected client_id.");
        }

        if (string.IsNullOrEmpty(jwt.Id))
        {
            return ClientAssertionValidationResult.Failure("the assertion is missing jti.");
        }

        return ClientAssertionValidationResult.Success(issuer, jwt.Id, new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero));
    }
}
