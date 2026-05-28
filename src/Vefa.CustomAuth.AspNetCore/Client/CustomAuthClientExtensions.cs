using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Vefa.CustomAuth.AspNetCore.Client;

/// <summary>
/// Extension methods for wiring a Vefa.CustomAuth OIDC relying party into an
/// ASP.NET Core application with sensible defaults (PKCE, code flow, cookie
/// session, name claim mapped, refresh tokens persisted).
/// </summary>
public static class CustomAuthClientExtensions
{
    /// <summary>
    /// Registers cookie + OpenID Connect authentication configured against a
    /// Vefa.CustomAuth authorization server. Only <see cref="CustomAuthClientOptions.Authority"/>
    /// and <see cref="CustomAuthClientOptions.ClientId"/> are required; the rest
    /// keep secure defaults unless overridden.
    /// </summary>
    public static AuthenticationBuilder AddCustomAuthClient(
        this IServiceCollection services,
        Action<CustomAuthClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new CustomAuthClientOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            throw new ArgumentException($"{nameof(CustomAuthClientOptions.Authority)} must be specified.", nameof(configure));
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            throw new ArgumentException($"{nameof(CustomAuthClientOptions.ClientId)} must be specified.", nameof(configure));
        }

        return services
            .AddAuthentication(auth =>
            {
                auth.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                auth.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                auth.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(oidc =>
            {
                oidc.Authority = options.Authority;
                oidc.RequireHttpsMetadata = options.RequireHttpsMetadata;
                oidc.ClientId = options.ClientId;
                if (!string.IsNullOrEmpty(options.ClientSecret))
                {
                    oidc.ClientSecret = options.ClientSecret;
                }

                oidc.ResponseType = OpenIdConnectResponseType.Code;
                oidc.ResponseMode = OpenIdConnectResponseMode.Query;
                oidc.UsePkce = true;
                oidc.SaveTokens = options.SaveTokens;
                oidc.GetClaimsFromUserInfoEndpoint = options.GetClaimsFromUserInfoEndpoint;
                oidc.MapInboundClaims = false;
                oidc.CallbackPath = options.CallbackPath;
                oidc.SignedOutCallbackPath = options.SignedOutCallbackPath;
                oidc.SignedOutRedirectUri = options.SignedOutRedirectUri;

                oidc.Scope.Clear();
                foreach (var scope in options.Scopes)
                {
                    oidc.Scope.Add(scope);
                }
                foreach (var scope in options.AdditionalScopes)
                {
                    oidc.Scope.Add(scope);
                }

                oidc.TokenValidationParameters.NameClaimType = "name";
                oidc.ProtocolValidator.RequireNonce = options.RequireNonce;
            });
    }

    /// <summary>
    /// Maps a convenience sign-out endpoint at <paramref name="pattern"/> that signs
    /// out of the local cookie and the upstream authorization server in one call.
    /// </summary>
    public static IEndpointConventionBuilder MapCustomAuthSignOut(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/logout")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(pattern);

        return endpoints.MapGet(pattern, async (HttpContext context) =>
        {
            var properties = new AuthenticationProperties { RedirectUri = "/" };
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
            return Results.SignOut(properties, new[] { OpenIdConnectDefaults.AuthenticationScheme });
        });
    }
}
