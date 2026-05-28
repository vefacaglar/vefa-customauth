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

internal sealed class SessionCookieService
{
    private readonly ICustomAuthSessionManager _sessionManager;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly IDataProtector _protector;
    private readonly TimeProvider _timeProvider;

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
