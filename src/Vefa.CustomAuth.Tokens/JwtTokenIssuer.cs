using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.Tokens;

/// <summary>
/// Issues JWT access and id tokens, plus an opaque random refresh token.
/// Persisting the refresh token is the caller's responsibility — the issuer returns
/// the raw value and the caller must hash it via <see cref="TokenHasher"/> before storage.
/// </summary>
public sealed class JwtTokenIssuer : ITokenIssuer
{
    private readonly ISigningCredentialsProvider _signingCredentialsProvider;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenIssuer(
        ISigningCredentialsProvider signingCredentialsProvider,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider? timeProvider = null)
    {
        _signingCredentialsProvider = signingCredentialsProvider ?? throw new ArgumentNullException(nameof(signingCredentialsProvider));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<IssuedTokens> IssueAsync(TokenIssueRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var opts = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(opts.Issuer))
        {
            throw new InvalidOperationException("CustomAuthOptions.Issuer is not configured.");
        }

        var now = _timeProvider.GetUtcNow();
        var credentials = await _signingCredentialsProvider.GetActiveAsync(cancellationToken).ConfigureAwait(false);

        var accessToken = CreateAccessToken(request, opts, now, credentials);
        var idToken = CreateIdToken(request, opts, now, credentials);
        var refreshToken = TokenHasher.CreateOpaqueToken();

        return new IssuedTokens
        {
            AccessToken = accessToken,
            IdToken = idToken,
            RefreshToken = refreshToken,
            AccessTokenExpiresInSeconds = (int)opts.AccessTokenLifetime.TotalSeconds,
        };
    }

    private string CreateAccessToken(TokenIssueRequest request, CustomAuthOptions opts, DateTimeOffset now, SigningCredentials credentials)
    {
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = request.Subject,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            ["scope"] = request.Scope,
            ["client_id"] = request.ClientId,
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            // NOTE: v0.1 simplification — access_token aud = client_id. A resource/audience model will be introduced in v0.2.
            Audience = request.ClientId,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(opts.AccessTokenLifetime).UtcDateTime,
            SigningCredentials = credentials,
            Claims = claims,
        };

        return _handler.CreateToken(descriptor);
    }

    private string CreateIdToken(TokenIssueRequest request, CustomAuthOptions opts, DateTimeOffset now, SigningCredentials credentials)
    {
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = request.Subject,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
        };

        if (request.AuthTime is { } authTime)
        {
            claims["auth_time"] = authTime.ToUnixTimeSeconds();
        }

        if (!string.IsNullOrEmpty(request.Nonce))
        {
            claims["nonce"] = request.Nonce;
        }

        if (request.AdditionalClaims is not null)
        {
            foreach (var (key, value) in request.AdditionalClaims)
            {
                if (!claims.ContainsKey(key))
                {
                    claims[key] = value;
                }
            }
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = opts.Issuer,
            Audience = request.ClientId,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(opts.IdTokenLifetime).UtcDateTime,
            SigningCredentials = credentials,
            Claims = claims,
        };

        return _handler.CreateToken(descriptor);
    }
}
