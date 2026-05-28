using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Tokens.Signing;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Maps the Vefa.CustomAuth OAuth2 / OIDC protocol endpoints onto an
/// <see cref="IEndpointRouteBuilder"/>. The library deliberately does not ship a
/// rendered login or logout UI — the host owns those pages and points at them via
/// <see cref="CustomAuthOptions.LoginPath"/> and <see cref="CustomAuthOptions.LogoutPath"/>.
/// </summary>
public static class CustomAuthEndpointRouteExtensions
{
    /// <summary>
    /// Maps the protocol endpoints: discovery, JWKS, authorize, token, userinfo,
    /// revoke, RP-initiated logout, and the credential-validation POST handler for
    /// <see cref="CustomAuthOptions.LoginPath"/>.
    /// </summary>
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
                end_session_endpoint = $"{issuer}/connect/logout",
                userinfo_endpoint = $"{issuer}/connect/userinfo",
                revocation_endpoint = $"{issuer}/connect/revoke",
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
                token_endpoint_auth_methods_supported = new[] { "none" },
                code_challenge_methods_supported = new[] { "S256" },
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

        var optionsMonitor = (IOptionsMonitor<CustomAuthOptions>?)endpoints.ServiceProvider.GetService(typeof(IOptionsMonitor<CustomAuthOptions>));
        var options = optionsMonitor?.CurrentValue ?? new CustomAuthOptions();

        endpoints.MapPost(options.LoginPath, (
            HttpContext context,
            LoginEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapGet("/connect/logout", (
            HttpContext context,
            LogoutEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapPost("/connect/logout", (
            HttpContext context,
            LogoutEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapGet("/connect/userinfo", (
            HttpContext context,
            UserInfoEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapPost("/connect/userinfo", (
            HttpContext context,
            UserInfoEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(context, cancellationToken));

        endpoints.MapPost("/connect/revoke", (
            HttpRequest request,
            RevocationEndpointService service,
            CancellationToken cancellationToken) => service.HandleAsync(request, cancellationToken));

        return endpoints;
    }
}
