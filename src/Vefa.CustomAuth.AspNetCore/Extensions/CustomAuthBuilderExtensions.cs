using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.Tokens;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthBuilderExtensions
{
    /// <summary>
    /// Registers the JWT signing infrastructure in DI:
    /// <see cref="ISigningCredentialsProvider"/> (RSA-based) and
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
}
