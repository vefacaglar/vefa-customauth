using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Vefa.CustomAuth.AspNetCore.Endpoints;
using Vefa.CustomAuth.AspNetCore.Services;
using Vefa.CustomAuth.AspNetCore.Validation;
using Vefa.CustomAuth.Core.Options;
using Vefa.CustomAuth.Core.Services;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Dependency injection extension methods for Vefa.CustomAuth.
/// </summary>
public static class CustomAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers the core Vefa.CustomAuth services and options.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">The options configuration callback.</param>
    /// <returns>A builder that can be used to register token signing and stores.</returns>
    public static CustomAuthBuilder AddCustomAuth(this IServiceCollection services, Action<CustomAuthOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<CustomAuthOptions>()
            .Configure(configure)
            .ValidateOnStart();

        services.AddAntiforgery();
        services.AddMemoryCache();
        services.TryAddSingleton<IValidateOptions<CustomAuthOptions>, CustomAuthOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<Tokens.ClientAssertion.IClientAssertionValidator, Tokens.ClientAssertion.ClientAssertionValidator>();
        services.TryAddSingleton<Services.IClientAssertionReplayCache, Services.MemoryClientAssertionReplayCache>();
        services.TryAddScoped<AuthorizationEndpointService>();
        services.TryAddScoped<LoginEndpointService>();
        services.TryAddScoped<ClientAuthenticationService>();
        services.TryAddScoped<TokenEndpointService>();
        services.TryAddScoped<SessionCookieService>();
        services.TryAddScoped<LogoutEndpointService>();
        services.TryAddScoped<UserInfoEndpointService>();
        services.TryAddScoped<RevocationEndpointService>();
        services.TryAddScoped<ICustomAuthLoginAttemptTracker, DefaultLoginAttemptTracker>();
        services.TryAddScoped<ICustomAuthProfileService, DefaultProfileService>();

        // Register Managers as Scoped
        services.TryAddScoped<Core.Managers.ICustomAuthClientManager, Core.Managers.CustomAuthClientManager>();
        services.TryAddScoped<Core.Managers.ICustomAuthScopeManager, Core.Managers.CustomAuthScopeManager>();
        services.TryAddScoped<Core.Managers.ICustomAuthSessionManager, Core.Managers.CustomAuthSessionManager>();
        services.TryAddScoped<Core.Managers.ICustomAuthTokenManager, Core.Managers.CustomAuthTokenManager>();
        services.TryAddScoped<Core.Managers.ICustomAuthSigningKeyManager, Core.Managers.CustomAuthSigningKeyManager>();
        services.TryAddScoped<Core.Managers.ICustomAuthAuditLogManager, Core.Managers.CustomAuthAuditLogManager>();

        // Register default fallback Scope and AuditLog stores
        var defaultScopes = new List<Core.Models.CustomAuthScope>
        {
            new() { Name = "openid", DisplayName = "OpenID", Description = "Access user identifier.", Required = true },
            new() { Name = "profile", DisplayName = "Profile", Description = "Access user profile details." },
            new() { Name = "email", DisplayName = "Email", Description = "Access user email address." },
            new() { Name = "offline_access", DisplayName = "Offline Access", Description = "Allow background refresh token exchange." }
        };
        services.TryAddSingleton<Core.Stores.ICustomAuthScopeStore>(_ => new Stores.InMemory.InMemoryScopeStore(defaultScopes));
        services.TryAddSingleton<Core.Stores.ICustomAuthAuditLogStore, Stores.InMemory.InMemoryAuditLogStore>();

        return new CustomAuthBuilder(services);
    }
}
