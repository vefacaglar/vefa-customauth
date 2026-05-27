using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthEndpointRouteExtensions
{
    public static IEndpointRouteBuilder MapVefaCustomAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet("/.well-known/openid-configuration", (IOptionsMonitor<CustomAuthOptions> options) =>
        {
            var issuer = options.CurrentValue.Issuer.TrimEnd('/');
            return Results.Json(new
            {
                issuer,
                authorization_endpoint = $"{issuer}/connect/authorize",
                token_endpoint = $"{issuer}/connect/token",
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
                token_endpoint_auth_methods_supported = new[] { "none" },
                code_challenge_methods_supported = new[] { "S256", "plain" },
            });
        });

        endpoints.MapGet("/.well-known/jwks.json", async (
            ISigningCredentialsProvider signingCredentialsProvider,
            CancellationToken cancellationToken) =>
        {
            var keys = await signingCredentialsProvider.GetJsonWebKeySetAsync(cancellationToken).ConfigureAwait(false);
            return Results.Json(new
            {
                keys = keys.Select(key => new
                {
                    kty = key.Kty,
                    use = key.Use,
                    alg = key.Alg,
                    kid = key.Kid,
                    n = key.N,
                    e = key.E,
                }),
            });
        });

        endpoints.MapGet("/connect/authorize", (
            HttpContext context,
            AuthorizationEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapPost("/connect/token", (
            HttpRequest request,
            TokenEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(request, cancellationToken));

        endpoints.MapGet("/login", (HttpRequest request, LoginEndpointService service) => service.Render(request));

        endpoints.MapPost("/login", (
            HttpContext context,
            LoginEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        return endpoints;
    }
}
