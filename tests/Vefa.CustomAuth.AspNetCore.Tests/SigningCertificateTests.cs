using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.AspNetCore.Extensions;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Tests;

public sealed class SigningCertificateTests
{
    // Generated once for the whole class. Returns null when the environment cannot create/import a
    // certificate with a private key (e.g. a sandbox without keychain access); the certificate-backed
    // assertions then skip rather than fail. CI (Linux/Windows) exercises them.
    private static readonly X509Certificate2? SigningCertificate = TryCreateCertificate();

    [Fact]
    public async Task CertificateProviderPublishesItsKeyAndSignsVerifiableTokens()
    {
        if (SigningCertificate is null)
        {
            return;
        }

        var provider = new CertificateSigningCredentialsProvider(SigningCertificate);

        var credentials = await provider.GetActiveAsync();
        var jwks = await provider.GetJsonWebKeySetAsync();
        var jwk = Assert.Single(jwks);

        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("sig", jwk.Use);
        Assert.Equal(credentials.Key.KeyId, jwk.Kid);

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "http://localhost",
            Audience = "test-audience",
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = credentials,
        });

        Assert.Equal(jwk.Kid, handler.ReadJsonWebToken(token).Kid);

        var validation = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "http://localhost",
            ValidateAudience = true,
            ValidAudience = "test-audience",
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = jwk,
            ValidateLifetime = true,
        });

        Assert.True(validation.IsValid, validation.Exception?.Message);
    }

    [Fact]
    public void CertificateWithoutPrivateKeyIsRejected()
    {
        if (SigningCertificate is null)
        {
            return;
        }

        using var publicOnly = new X509Certificate2(SigningCertificate.Export(X509ContentType.Cert));

        Assert.Throws<ArgumentException>(() => new CertificateSigningCredentialsProvider(publicOnly));
    }

    [Fact]
    public void AddSigningCertificateOverridesTheStoreBackedProvider()
    {
        if (SigningCertificate is null)
        {
            return;
        }

        using var provider = BuildProvider(builder => builder.AddSigningCertificate(SigningCertificate));
        using var scope = provider.CreateScope();

        var signing = scope.ServiceProvider.GetRequiredService<ISigningCredentialsProvider>();
        Assert.IsType<CertificateSigningCredentialsProvider>(signing);
    }

    [Fact]
    public void WithoutCertificateTheStoreBackedProviderIsUsed()
    {
        using var provider = BuildProvider(_ => { });
        using var scope = provider.CreateScope();

        var signing = scope.ServiceProvider.GetRequiredService<ISigningCredentialsProvider>();
        Assert.IsType<RsaSigningCredentialsProvider>(signing);
    }

    private static ServiceProvider BuildProvider(Action<CustomAuthBuilder> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        var builder = services
            .AddCustomAuth(options =>
            {
                options.Issuer = "http://localhost";
                options.RequireHttps = false;
            })
            .AddJwtTokenSigning()
            .AddInMemoryStores(_ => { });

        configure(builder);

        return services.BuildServiceProvider();
    }

    private static X509Certificate2? TryCreateCertificate()
    {
        var directory = Path.Combine(Path.GetTempPath(), "vca-cert-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var keyPath = Path.Combine(directory, "key.pem");
            var certPath = Path.Combine(directory, "cert.pem");
            var pfxPath = Path.Combine(directory, "cert.pfx");

            if (!RunOpenSsl($"req -x509 -newkey rsa:2048 -keyout \"{keyPath}\" -out \"{certPath}\" -days 2 -nodes -subj \"/CN=Vefa.CustomAuth Test Signing\"")
                || !RunOpenSsl($"pkcs12 -export -inkey \"{keyPath}\" -in \"{certPath}\" -out \"{pfxPath}\" -passout pass:test"))
            {
                return null;
            }

            return new X509Certificate2(File.ReadAllBytes(pfxPath), "test", X509KeyStorageFlags.Exportable);
        }
        catch
        {
            return null;
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch
            {
                // best effort cleanup
            }
        }
    }

    private static bool RunOpenSsl(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("openssl", arguments)
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            });

            if (process is null)
            {
                return false;
            }

            process.WaitForExit(30_000);
            return process.HasExited && process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
