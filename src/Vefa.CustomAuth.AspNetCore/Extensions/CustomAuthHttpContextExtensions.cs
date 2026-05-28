using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Provides extension methods on <see cref="HttpContext"/> to support custom authentication flows (e.g., in Razor Pages).
/// </summary>
public static class CustomAuthHttpContextExtensions
{
    /// <summary>
    /// Signs in the specified user by creating a new active SSO session in the session store and appending the encrypted SSO cookie.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="userId">The ID of the authenticated user.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The newly created <see cref="CustomAuthSession"/> object.</returns>
    public static async Task<CustomAuthSession> SignInCustomAuthAsync(
        this HttpContext context,
        string userId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrEmpty(userId);

        var sessionManager = context.RequestServices.GetRequiredService<ICustomAuthSessionManager>();
        var sessionCookieService = context.RequestServices.GetRequiredService<SessionCookieService>();
        var optionsMonitor = context.RequestServices.GetRequiredService<IOptionsMonitor<CustomAuthOptions>>();
        var timeProvider = context.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System;

        var now = timeProvider.GetUtcNow();
        var session = new CustomAuthSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            CreatedAt = now,
            ExpiresAt = now.Add(optionsMonitor.CurrentValue.RefreshTokenLifetime),
        };

        await sessionManager.CreateAsync(session, cancellationToken).ConfigureAwait(false);
        sessionCookieService.SignIn(context, session);

        return session;
    }

    /// <summary>
    /// Signs out the current user by revoking their active SSO session from the store and deleting the SSO cookie.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous sign-out operation.</returns>
    public static async Task SignOutCustomAuthAsync(
        this HttpContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var sessionCookieService = context.RequestServices.GetRequiredService<SessionCookieService>();
        var sessionManager = context.RequestServices.GetRequiredService<ICustomAuthSessionManager>();

        var session = await sessionCookieService.GetCurrentSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session is not null)
        {
            await sessionManager.RevokeAsync(session.Id, cancellationToken).ConfigureAwait(false);
        }

        sessionCookieService.SignOut(context);
    }
}
