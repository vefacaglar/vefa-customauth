using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Endpoints;

internal sealed class SessionCookieService
{
    private readonly ICustomAuthSessionStore _sessionStore;
    private readonly IOptionsMonitor<CustomAuthOptions> _options;
    private readonly TimeProvider _timeProvider;

    public SessionCookieService(
        ICustomAuthSessionStore sessionStore,
        IOptionsMonitor<CustomAuthOptions> options,
        TimeProvider timeProvider)
    {
        _sessionStore = sessionStore ?? throw new ArgumentNullException(nameof(sessionStore));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    public async Task<CustomAuthSession?> GetCurrentSessionAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = _options.CurrentValue;
        if (!context.Request.Cookies.TryGetValue(options.CookieName, out var rawSessionId)
            || !Guid.TryParse(rawSessionId, out var sessionId))
        {
            return null;
        }

        var session = await _sessionStore.FindAsync(sessionId, cancellationToken).ConfigureAwait(false);
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
        context.Response.Cookies.Append(
            options.CookieName,
            session.Id.ToString("D"),
            new CookieOptions
            {
                HttpOnly = true,
                Secure = options.RequireHttps,
                SameSite = SameSiteMode.Lax,
                Expires = session.ExpiresAt,
            });
    }
}
