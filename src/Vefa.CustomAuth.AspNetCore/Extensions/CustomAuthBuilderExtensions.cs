using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Tokens;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthBuilderExtensions
{
    /// <summary>
    /// Registers the JWT signing infrastructure in DI:
    /// <see cref="ISigningCredentialsProvider"/> (RSA-based, persisted in the signing key store) and
    /// <see cref="ITokenIssuer"/> (JWT access + id token + opaque refresh).
    /// </summary>
    public static CustomAuthBuilder AddJwtTokenSigning(this CustomAuthBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddScoped<ISigningCredentialsProvider, RsaSigningCredentialsProvider>();
        builder.Services.TryAddScoped<ITokenIssuer, JwtTokenIssuer>();

        return builder;
    }

    /// <summary>
    /// Signs tokens with a fixed X.509 certificate instead of the auto-generated key persisted in the
    /// signing key store. When this is configured the certificate is used; otherwise signing falls back
    /// to the store-backed key registered by <see cref="AddJwtTokenSigning"/>. Use this when the signing
    /// key must be operator-controlled and identical across every instance behind a load balancer.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="certificate">The signing certificate; it must contain an RSA private key.</param>
    /// <param name="algorithm">The signing algorithm (defaults to RS256).</param>
    public static CustomAuthBuilder AddSigningCertificate(
        this CustomAuthBuilder builder,
        X509Certificate2 certificate,
        string algorithm = SecurityAlgorithms.RsaSha256)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(certificate);

        // Replace (not TryAdd) so the certificate provider wins over the store-backed provider,
        // regardless of registration order.
        builder.Services.Replace(ServiceDescriptor.Singleton<ISigningCredentialsProvider>(
            _ => new CertificateSigningCredentialsProvider(certificate, algorithm)));

        return builder;
    }

    /// <summary>
    /// Loads a PFX (PKCS#12) file and signs tokens with it. See
    /// <see cref="AddSigningCertificate(CustomAuthBuilder, X509Certificate2, string)"/>.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="pfxFilePath">Path to the PFX file.</param>
    /// <param name="password">The PFX password, or null when the file is unprotected.</param>
    /// <param name="algorithm">The signing algorithm (defaults to RS256).</param>
    public static CustomAuthBuilder AddSigningCertificate(
        this CustomAuthBuilder builder,
        string pfxFilePath,
        string? password = null,
        string algorithm = SecurityAlgorithms.RsaSha256)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(pfxFilePath);

        var certificate = new X509Certificate2(pfxFilePath, password, X509KeyStorageFlags.Exportable);
        return builder.AddSigningCertificate(certificate, algorithm);
    }
}
