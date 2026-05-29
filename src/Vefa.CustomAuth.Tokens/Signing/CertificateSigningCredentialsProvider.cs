using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Vefa.CustomAuth.Tokens.Signing;

/// <summary>
/// An <see cref="ISigningCredentialsProvider"/> backed by a fixed X.509 certificate (e.g. a PFX).
/// Use this when the signing key must be operator-controlled and identical across every instance
/// behind a load balancer, instead of the auto-generated, database-persisted key. The certificate's
/// private key signs tokens and its public key is published at the JWKS endpoint.
/// </summary>
public sealed class CertificateSigningCredentialsProvider : ISigningCredentialsProvider
{
    private readonly SigningCredentials _signingCredentials;
    private readonly IReadOnlyList<JsonWebKey> _jsonWebKeys;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningCredentialsProvider"/> class.
    /// </summary>
    /// <param name="certificate">The signing certificate, which must contain an RSA private key.</param>
    /// <param name="algorithm">The signing algorithm (defaults to RS256).</param>
    public CertificateSigningCredentialsProvider(X509Certificate2 certificate, string algorithm = SecurityAlgorithms.RsaSha256)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("The signing certificate must include a private key.", nameof(certificate));
        }

        var privateKey = certificate.GetRSAPrivateKey()
            ?? throw new ArgumentException("Only RSA signing certificates are supported.", nameof(certificate));

        // A stable key id derived from the certificate thumbprint, so the JWKS `kid` and the token
        // header `kid` match across every instance that loads the same certificate.
        var keyId = Base64UrlEncoder.Encode(certificate.GetCertHash(HashAlgorithmName.SHA256));
        var securityKey = new RsaSecurityKey(privateKey) { KeyId = keyId };
        _signingCredentials = new SigningCredentials(securityKey, algorithm);

        using var publicKey = certificate.GetRSAPublicKey()
            ?? throw new ArgumentException("The signing certificate has no RSA public key.", nameof(certificate));
        var parameters = publicKey.ExportParameters(includePrivateParameters: false);

        _jsonWebKeys = new[]
        {
            new JsonWebKey
            {
                Kty = "RSA",
                Use = "sig",
                Alg = algorithm,
                Kid = keyId,
                N = Base64UrlEncoder.Encode(parameters.Modulus!),
                E = Base64UrlEncoder.Encode(parameters.Exponent!),
            },
        };
    }

    /// <inheritdoc />
    public Task<SigningCredentials> GetActiveAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_signingCredentials);

    /// <inheritdoc />
    public Task<IReadOnlyList<JsonWebKey>> GetJsonWebKeySetAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_jsonWebKeys);
}
