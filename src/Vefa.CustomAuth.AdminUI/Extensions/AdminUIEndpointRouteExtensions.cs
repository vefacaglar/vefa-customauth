using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Vefa.CustomAuth.AdminUI.Options;
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
    /// <returns>A <see cref="RouteGroupBuilder"/> covering every Admin UI route, so callers can chain additional conventions.</returns>
    /// <remarks>
    /// By default, all Admin UI routes (dashboard, static assets, admin APIs) require an authenticated request
    /// that satisfies the application's default authorization policy. Opt out via
    /// <see cref="CustomAuthAdminUIOptions.AllowAnonymous"/> only for local development or trusted networks.
    /// </remarks>
    public static RouteGroupBuilder MapCustomAuthAdminUI(
        this IEndpointRouteBuilder endpoints,
        string pathPrefix = "/customauth")
        => endpoints.MapCustomAuthAdminUI(options => options.PathPrefix = pathPrefix);

    /// <summary>
    /// Maps the embedded Vefa.CustomAuth Admin UI dashboard and administrative CRUD API endpoints.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="configure">The Admin UI options configuration callback.</param>
    /// <returns>A <see cref="RouteGroupBuilder"/> covering every Admin UI route, so callers can chain additional conventions.</returns>
    /// <remarks>
    /// By default, all Admin UI routes (dashboard, static assets, admin APIs) require an authenticated request
    /// that satisfies the application's default authorization policy. Opt out via
    /// <see cref="CustomAuthAdminUIOptions.AllowAnonymous"/> only for local development or trusted networks.
    /// </remarks>
    public static RouteGroupBuilder MapCustomAuthAdminUI(
        this IEndpointRouteBuilder endpoints,
        Action<CustomAuthAdminUIOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new CustomAuthAdminUIOptions();
        configure(options);
        ValidateOptions(options);

        var normalizedPrefix = "/" + options.PathPrefix.Trim('/');
        var assembly = typeof(AdminUIEndpointRouteExtensions).Assembly;

        var group = endpoints.MapGroup(normalizedPrefix);
        group.AddEndpointFilter<AdminUIAntiforgeryFilter>();

        // 1. Serve embedded static SPA resources
        group.MapGet("", async (
            HttpContext context, 
            [FromServices] Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery) =>
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

            var tokens = antiforgery.GetAndStoreTokens(context);
            if (tokens.RequestToken is not null)
            {
                html = html.Replace("__RequestVerificationToken__", tokens.RequestToken);
            }

            return Results.Content(html, "text/html", Encoding.UTF8);
        });

        group.MapGet("/css/admin.css", async () =>
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

        group.MapGet("/js/admin.js", async () =>
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
        group.MapGet("/api/clients", async (
            [FromQuery] int page,
            [FromQuery] int pageSize,
            [FromQuery] string? search,
            ICustomAuthClientManager clientManager,
            CancellationToken cancellationToken) =>
        {
            var pagedRequest = CreatePagedRequest(page, pageSize, search, options);

            var result = await clientManager.GetPagedAsync(pagedRequest, cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        group.MapPost("/api/clients", async (
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

        group.MapPut("/api/clients/{clientId}", async (
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

        group.MapDelete("/api/clients/{clientId}", async (
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

        // Scope management endpoints
        group.MapGet("/api/scopes", async (
            ICustomAuthScopeManager scopeManager,
            CancellationToken cancellationToken) =>
        {
            var result = await scopeManager.GetAllAsync(cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        group.MapPost("/api/scopes", async (
            [FromBody] CustomAuthScope scope,
            ICustomAuthScopeManager scopeManager,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await scopeManager.CreateAsync(scope, cancellationToken).ConfigureAwait(false);
                return Results.Created($"{normalizedPrefix}/api/scopes/{scope.Name}", scope);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        group.MapPut("/api/scopes/{name}", async (
            [FromRoute] string name,
            [FromBody] CustomAuthScope scope,
            ICustomAuthScopeManager scopeManager,
            CancellationToken cancellationToken) =>
        {
            if (!string.Equals(name, scope.Name, StringComparison.Ordinal))
            {
                return Results.BadRequest("Scope name mismatch.");
            }

            try
            {
                await scopeManager.UpdateAsync(scope, cancellationToken).ConfigureAwait(false);
                return Results.Ok(scope);
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        group.MapDelete("/api/scopes/{name}", async (
            [FromRoute] string name,
            ICustomAuthScopeManager scopeManager,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await scopeManager.DeleteAsync(name, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        // Session viewer endpoints
        group.MapGet("/api/sessions", async (
            [FromQuery] int page,
            [FromQuery] int pageSize,
            [FromQuery] string? search,
            ICustomAuthSessionManager sessionManager,
            CancellationToken cancellationToken) =>
        {
            var pagedRequest = CreatePagedRequest(page, pageSize, search, options);

            var result = await sessionManager.GetPagedAsync(pagedRequest, cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        group.MapPost("/api/sessions/{sessionId}/revoke", async (
            [FromRoute] Guid sessionId,
            ICustomAuthSessionManager sessionManager,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await sessionManager.RevokeAsync(sessionId, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        // Refresh token viewer endpoints
        group.MapGet("/api/refresh-tokens", async (
            [FromQuery] int page,
            [FromQuery] int pageSize,
            [FromQuery] string? search,
            ICustomAuthTokenManager tokenManager,
            CancellationToken cancellationToken) =>
        {
            var pagedRequest = CreatePagedRequest(page, pageSize, search, options);

            var result = await tokenManager.GetRefreshTokensPagedAsync(pagedRequest, cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        group.MapPost("/api/refresh-tokens/{tokenId}/revoke", async (
            [FromRoute] Guid tokenId,
            ICustomAuthTokenManager tokenManager,
            TimeProvider timeProvider,
            CancellationToken cancellationToken) =>
        {
            try
            {
                await tokenManager.RevokeRefreshTokenAsync(tokenId, timeProvider.GetUtcNow(), cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(ex.Message);
            }
        });

        // Signing key viewer endpoints
        group.MapGet("/api/signing-keys", async (
            ICustomAuthSigningKeyManager signingKeyManager,
            CancellationToken cancellationToken) =>
        {
            var keys = await signingKeyManager.GetAllAsync(cancellationToken).ConfigureAwait(false);
            var safeKeys = keys.Select(k => new
            {
                k.KeyId,
                k.Algorithm,
                k.CreatedAt,
                k.RetiredAt,
                k.IsActive,
                PublicKeyPem = k.PublicKeyPem
            }).ToList();
            return Results.Ok(safeKeys);
        });

        // Audit log viewer endpoints
        group.MapGet("/api/audit-logs", async (
            [FromQuery] int page,
            [FromQuery] int pageSize,
            [FromQuery] string? search,
            ICustomAuthAuditLogManager auditLogManager,
            CancellationToken cancellationToken) =>
        {
            var pagedRequest = CreatePagedRequest(page, pageSize, search, options);

            var result = await auditLogManager.GetPagedAsync(pagedRequest, cancellationToken).ConfigureAwait(false);
            return Results.Ok(result);
        });

        if (options.AllowAnonymous)
        {
            group.AllowAnonymous();
        }
        else if (!string.IsNullOrWhiteSpace(options.AuthorizationPolicyName))
        {
            group.RequireAuthorization(options.AuthorizationPolicyName);
        }
        else
        {
            group.RequireAuthorization();
        }

        return group;
    }

    private static CustomAuthPagedRequest CreatePagedRequest(
        int page,
        int pageSize,
        string? search,
        CustomAuthAdminUIOptions options)
    {
        var requestedPageSize = pageSize > 0 ? pageSize : options.DefaultPageSize;

        return new CustomAuthPagedRequest
        {
            Page = page > 0 ? page : 1,
            PageSize = Math.Min(requestedPageSize, options.MaxPageSize),
            Search = search
        };
    }

    private static void ValidateOptions(CustomAuthAdminUIOptions options)
    {
        ArgumentException.ThrowIfNullOrEmpty(options.PathPrefix);

        if (options.DefaultPageSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Default page size must be greater than zero.");
        }

        if (options.MaxPageSize < options.DefaultPageSize)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Maximum page size must be greater than or equal to the default page size.");
        }
    }

    private sealed class AdminUIAntiforgeryFilter : IEndpointFilter
    {
        private readonly Microsoft.AspNetCore.Antiforgery.IAntiforgery _antiforgery;

        public AdminUIAntiforgeryFilter(Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery ?? throw new ArgumentNullException(nameof(antiforgery));
        }

        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var method = context.HttpContext.Request.Method;
            if (HttpMethods.IsPost(method) || HttpMethods.IsPut(method) || HttpMethods.IsDelete(method))
            {
                try
                {
                    await _antiforgery.ValidateRequestAsync(context.HttpContext).ConfigureAwait(false);
                }
                catch (Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException)
                {
                    return Results.BadRequest("Antiforgery token validation failed.");
                }
            }

            return await next(context).ConfigureAwait(false);
        }
    }
}
