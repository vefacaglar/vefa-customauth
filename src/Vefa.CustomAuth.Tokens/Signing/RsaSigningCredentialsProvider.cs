using Microsoft.IdentityModel.Tokens;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.Tokens.Signing;

/// <summary>
/// Reads the active key from <see cref="ICustomAuthSigningKeyStore"/> and produces
/// <see cref="SigningCredentials"/> for JWT signing plus a <see cref="JsonWebKey"/>
/// list for the JWKS endpoint.
///
/// If the store has no active key, a new RSA key is generated and persisted on first use.
/// In production this bootstrap should be performed explicitly by an administrator.
/// </summary>
public sealed class RsaSigningCredentialsProvider : ISigningCredentialsProvider
{
    private readonly ICustomAuthSigningKeyStore _keyStore;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _bootstrapLock = new(1, 1);

    public RsaSigningCredentialsProvider(ICustomAuthSigningKeyStore keyStore, TimeProvider? timeProvider = null)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<SigningCredentials> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        var key = await _keyStore.GetActiveAsync(cancellationToken).ConfigureAwait(false)
                  ?? await BootstrapAsync(cancellationToken).ConfigureAwait(false);

        var rsa = RsaKeyGenerator.ImportPrivateKey(key);
        var securityKey = new RsaSecurityKey(rsa) { KeyId = key.KeyId };

        return new SigningCredentials(securityKey, key.Algorithm);
    }

    public async Task<IReadOnlyList<JsonWebKey>> GetJsonWebKeySetAsync(CancellationToken cancellationToken = default)
    {
        var keys = await _keyStore.GetAllAsync(cancellationToken).ConfigureAwait(false);

        if (keys.Count == 0)
        {
            await BootstrapAsync(cancellationToken).ConfigureAwait(false);
            keys = await _keyStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        }

        var result = new List<JsonWebKey>(keys.Count);
        foreach (var key in keys)
        {
            using var rsa = RsaKeyGenerator.ImportPublicKey(key);
            var parameters = rsa.ExportParameters(includePrivateParameters: false);

            result.Add(new JsonWebKey
            {
                Kty = "RSA",
                Use = "sig",
                Alg = key.Algorithm,
                Kid = key.KeyId,
                N = Base64UrlEncoder.Encode(parameters.Modulus!),
                E = Base64UrlEncoder.Encode(parameters.Exponent!),
            });
        }

        return result;
    }

    private async Task<Core.Models.CustomAuthSigningKey> BootstrapAsync(CancellationToken cancellationToken)
    {
        await _bootstrapLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existing = await _keyStore.GetActiveAsync(cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                return existing;
            }

            var generated = RsaKeyGenerator.Generate(_timeProvider.GetUtcNow());
            await _keyStore.StoreAsync(generated, cancellationToken).ConfigureAwait(false);
            return generated;
        }
        finally
        {
            _bootstrapLock.Release();
        }
    }
}
