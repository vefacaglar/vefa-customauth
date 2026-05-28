namespace Vefa.CustomAuth.Tokens.ClientAssertion;

/// <summary>
/// The outcome of validating a <c>private_key_jwt</c> client assertion.
/// </summary>
public sealed class ClientAssertionValidationResult
{
    private ClientAssertionValidationResult(bool succeeded, string? clientId, string? jti, DateTimeOffset? expiresAt, string? failureReason)
    {
        Succeeded = succeeded;
        ClientId = clientId;
        Jti = jti;
        ExpiresAt = expiresAt;
        FailureReason = failureReason;
    }

    /// <summary>Gets a value indicating whether the assertion is valid.</summary>
    public bool Succeeded { get; }

    /// <summary>Gets the authenticated client identifier (<c>iss</c>/<c>sub</c>) when successful.</summary>
    public string? ClientId { get; }

    /// <summary>Gets the assertion's unique identifier (<c>jti</c>) used for replay detection.</summary>
    public string? Jti { get; }

    /// <summary>Gets the assertion's expiry (<c>exp</c>), used to bound replay-cache retention.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Gets a short, non-sensitive description of why validation failed.</summary>
    public string? FailureReason { get; }

    /// <summary>Creates a successful result.</summary>
    public static ClientAssertionValidationResult Success(string clientId, string jti, DateTimeOffset expiresAt)
        => new(true, clientId, jti, expiresAt, failureReason: null);

    /// <summary>Creates a failed result with a non-sensitive reason for logging.</summary>
    public static ClientAssertionValidationResult Failure(string failureReason)
        => new(false, clientId: null, jti: null, expiresAt: null, failureReason);
}
