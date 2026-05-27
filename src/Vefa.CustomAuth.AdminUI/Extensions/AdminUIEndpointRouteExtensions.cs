using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;

namespace Vefa.CustomAuth.AdminUI.Extensions;

/// <summary>
/// Route builder extensions for mapping the embedded Vefa.CustomAuth Admin UI.
/// </summary>
public static class AdminUIEndpointRouteExtensions
{
    /// <summary>
    /// Maps the embedded Vefa.CustomAuth Admin UI dashboard and administrative CRUD API endpoints.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="pathPrefix">The URL path prefix where the Admin UI will be hosted. Defaults to "/customauth".</param>
    /// <returns>An endpoint convention builder to chain authentication/authorization policies.</returns>
    public static IEndpointConventionBuilder MapVefaCustomAuthAdminUI(
        this IEndpointRouteBuilder endpoints,
        string pathPrefix = "/customauth")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(pathPrefix);

        var normalizedPrefix = "/" + pathPrefix.Trim('/');
        var assembly = typeof(AdminUIEndpointRouteExtensions).Assembly;

        // 1. Serve embedded static SPA resources
        var indexRoute = endpoints.MapGet(normalizedPrefix, async (HttpContext context) =>
        {
            if (!context.Request.Path.Value!.EndsWith("/", StringComparison.Ordinal))
            {
                return Results.Redirect(context.Request.Path.Value + "/");
            }

            using var stream = assembly.GetManifestResourceStream("Vefa.CustomAuth.AdminUI.Resources.index.html");
            if (stream == null)
            {
                return Results.NotFound("Admin UI assets not found.");
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            var html = await reader.ReadToEndAsync().ConfigureAwait(false);
            return Results.Content(html, "text/html", Encoding.UTF8);
        });

        endpoints.MapGet($"{normalizedPrefix}/css/admin.css", async () =>
        {
            using var stream = assembly.GetManifestResourceStream("Vefa.CustomAuth.AdminUI.Resources.admin.css");
            if (stream == null)
            {
                return Results.NotFound();
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            var css = await reader.ReadToEndAsync().ConfigureAwait(false);
            return Results.Content(css, "text/css", Encoding.UTF8);
        });

        endpoints.MapGet($"{normalizedPrefix}/js/admin.js", async () =>
        {
            using var stream = assembly.GetManifestResourceStream("Vefa.CustomAuth.AdminUI.Resources.admin.js");
            if (stream == null)
            {
                return Results.NotFound();
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            var js = await reader.ReadToEndAsync().ConfigureAwait(false);
            return Results.Content(js, "application/javascript", Encoding.UTF8);
        });

        // 2. Map Administrative Minimal API endpoints calling Core Managers
        endpoints.MapGet($"{normalizedPrefix}/api/clients", async (
            [FromQuery] int page,
            [FromQuery] int pageSize,
            [FromQuery] string? search,
            ICustomAuthClientManager clientManager,
            CancellationToken cancellationToken) =>
        {
            var pagedRequest = new CustomAuthPagedRequest
            {
                Page = page > 0 ? page : 1,
                PageSize = pageSize > 0 ? pageSize : 10,
                Search = search
            };

            var result = await clientManager.GetPagedAsync(pagedRequest, cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        endpoints.MapPost($"{normalizedPrefix}/api/clients", async (
            [FromBody] CustomAuthClient client,
            ICustomAuthClientManager clientManager,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await clientManager.CreateAsync(client, cancellationToken).ConfigureAwait(false);
                return Results.Created($"{normalizedPrefix}/api/clients/{client.ClientId}", client);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        endpoints.MapPut($"{normalizedPrefix}/api/clients/{{clientId}}", async (
            [FromRoute] string clientId,
            [FromBody] CustomAuthClient client,
            ICustomAuthClientManager clientManager,
            CancellationToken cancellationToken) =>
        {
            if (!string.Equals(clientId, client.ClientId, StringComparison.Ordinal))
            {
                return Results.BadRequest("Client ID mismatch.");
            }

            try
            {
                await clientManager.UpdateAsync(client, cancellationToken).ConfigureAwait(false);
                return Results.Ok(client);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        endpoints.MapDelete($"{normalizedPrefix}/api/clients/{{clientId}}", async (
            [FromRoute] string clientId,
            ICustomAuthClientManager clientManager,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await clientManager.DeleteAsync(clientId, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        return indexRoute;
    }
}
