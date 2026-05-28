using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Managers;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

/// <summary>
/// Provides services for reading, writing, and deleting the CustomAuth SSO session cookie.
/// </summary>
public sealed class SessionCookieService
{
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionCookieService"/> class.
    /// </summary>
    /// <param name="sessionManager">The session manager.</param>
    /// <param name="options">The options monitor.</param>
    /// <param name="dataProtectionProvider">The data protection provider.</param>
    /// <param name="timeProvider">The time provider.</param>
    public SessionCookieService(
        ICustomAuthSessionManager sessionManager,
        IOptionsMonitor<CustomAuthOptions> options,
        IDataProtectionProvider dataProtectionProvider,
        TimeProvider timeProvider)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        ArgumentNullException.ThrowIfNull(dataProtectionProvider);
        _protector = dataProtectionProvider.CreateProtector("Vefa.CustomAuth.SessionCookie");
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    private string GetEffectiveCookieName()
    {
        var options = _options.CurrentValue;
        if (options.RequireHttps && !options.CookieName.StartsWith("__Host-", StringComparison.Ordinal))
        {
            return "__Host-" + options.CookieName.TrimStart('.');
        }
        return options.CookieName;
    }

    /// <summary>
    /// Gets the current active session associated with the request by looking up and decrypting the SSO cookie.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The active session if found and valid; otherwise, <c>null</c>.</returns>
    public async Task<CustomAuthSession?> GetCurrentSessionAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var cookieName = GetEffectiveCookieName();
        if (!context.Request.Cookies.TryGetValue(cookieName, out var rawCookieValue))
        {
            return null;
        }

        string rawSessionId;
        try
        {
            rawSessionId = _protector.Unprotect(rawCookieValue);
        }
        catch (CryptographicException)
        {
            return null; // Value was tampered with or key was rotated
        }

        if (!Guid.TryParse(rawSessionId, out var sessionId))
        {
            return null;
        }

        var session = await _sessionManager.FindAsync(sessionId, cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        if (session is null || session.RevokedAt is not null || session.ExpiresAt <= now)
        {
            return null;
        }

        return session;
    }

    /// <summary>
    /// Sets/appends the encrypted SSO session cookie for the specified session on the HTTP response.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="session">The active CustomAuth session.</param>
    public void SignIn(HttpContext context, CustomAuthSession session)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(session);

        var options = _options.CurrentValue;
        var protectedValue = _protector.Protect(session.Id.ToString("D"));
        var cookieName = GetEffectiveCookieName();

        context.Response.Cookies.Append(
            cookieName,
            protectedValue,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = options.RequireHttps,
                SameSite = SameSiteMode.Lax,
                Expires = session.ExpiresAt,
                Path = "/"
            });
    }

    /// <summary>
    /// Clears the SSO session cookie by deleting it from the HTTP response.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    public void SignOut(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = _options.CurrentValue;
        var cookieName = GetEffectiveCookieName();

        context.Response.Cookies.Delete(
            cookieName,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = options.RequireHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            });
    }
}
