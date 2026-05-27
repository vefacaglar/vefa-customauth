using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

/// <summary>
/// Builder for configuring seed data for in-memory stores.
/// </summary>
public sealed class InMemoryStoresBuilder
{
    /// <summary>
    /// Gets the list of clients to seed.
    /// </summary>
    public List<CustomAuthClient> Clients { get; } = new();

    /// <summary>
    /// Gets the list of users to seed.
    /// </summary>
    public List<InMemoryUserStore.SeedUser> Users { get; } = new();
}

/// <summary>
/// Dependency injection extension methods for registering in-memory stores.
/// </summary>
public static class InMemoryStoresExtensions
{
    /// <summary>
    /// Registers the in-memory store implementations as singletons.
    /// Optionally seeds clients and users via the configuration callback.
    /// Intended for samples, integration tests, and the v0.1 milestone only.
    /// </summary>
    /// <param name="builder">The custom auth builder.</param>
    /// <param name="configure">The configuration callback for seeding data.</param>
    /// <returns>The custom auth builder.</returns>
    public static CustomAuthBuilder AddInMemoryStores(
        this CustomAuthBuilder builder,
        Action<InMemoryStoresBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var setup = new InMemoryStoresBuilder();
        configure?.Invoke(setup);

        builder.Services.TryAddSingleton<ICustomAuthClientStore>(_ => new InMemoryClientStore(setup.Clients));
        builder.Services.TryAddSingleton<ICustomAuthUserStore>(_ => new InMemoryUserStore(setup.Users));
        builder.Services.TryAddSingleton<ICustomAuthAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
        builder.Services.TryAddSingleton<ICustomAuthRefreshTokenStore, InMemoryRefreshTokenStore>();
        builder.Services.TryAddSingleton<ICustomAuthSessionStore, InMemorySessionStore>();
        builder.Services.TryAddSingleton<ICustomAuthSigningKeyStore, InMemorySigningKeyStore>();

        // Register new Scope and AuditLog stores
        var defaultScopes = new List<CustomAuthScope>
        {
            new() { Name = "openid", DisplayName = "OpenID", Description = "Access user identifier.", Required = true },
            new() { Name = "profile", DisplayName = "Profile", Description = "Access user profile details." },
            new() { Name = "email", DisplayName = "Email", Description = "Access user email address." },
            new() { Name = "offline_access", DisplayName = "Offline Access", Description = "Allow background refresh token exchange." }
        };
        builder.Services.TryAddSingleton<ICustomAuthScopeStore>(_ => new InMemoryScopeStore(defaultScopes));
        builder.Services.TryAddSingleton<ICustomAuthAuditLogStore, InMemoryAuditLogStore>();

        return builder;
    }
}
