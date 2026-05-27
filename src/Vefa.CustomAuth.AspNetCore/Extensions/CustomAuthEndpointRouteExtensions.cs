using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public static class CustomAuthEndpointRouteExtensions
{
    public static IEndpointRouteBuilder MapVefaCustomAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet("/.well-known/openid-configuration", () => Results.Ok(new { todo = "discovery" }));
        endpoints.MapGet("/.well-known/jwks.json", () => Results.Ok(new { keys = Array.Empty<object>() }));
        endpoints.MapGet("/connect/authorize", () => Results.Ok("authorize"));
        endpoints.MapPost("/connect/token", () => Results.Ok("token"));
        endpoints.MapGet("/login", () => Results.Ok("login"));
        endpoints.MapPost("/login", () => Results.Ok("login-post"));

        return endpoints;
    }
}
