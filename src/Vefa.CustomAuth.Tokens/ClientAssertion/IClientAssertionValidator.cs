namespace Vefa.CustomAuth.Tokens.ClientAssertion;

/// <summary>
/// Validates <c>private_key_jwt</c> client assertions (RFC 7521 / 7523, OpenID Connect Core §9).
/// </summary>
public interface IClientAssertionValidator
{
    /// <summary>
    /// Validates a client assertion JWT against a client's registered public keys.
    /// </summary>
    /// <param name="assertion">The raw <c>client_assertion</c> JWT.</param>
    /// <param name="jwksJson">The client's public keys as a JWKS JSON document.</param>
    /// <param name="expectedClientId">
    /// The expected client identifier the assertion's <c>iss</c>/<c>sub</c> must equal, or null to
    /// accept whatever the assertion claims (the caller then trusts the returned client id).
    /// </param>
    /// <param name="validAudiences">The audiences the assertion's <c>aud</c> may match (issuer and token endpoint URL).</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The validation result.</returns>
    Task<ClientAssertionValidationResult> ValidateAsync(
        string assertion,
        string jwksJson,
        string? expectedClientId,
        IReadOnlyCollection<string> validAudiences,
        CancellationToken cancellationToken = default);
}
