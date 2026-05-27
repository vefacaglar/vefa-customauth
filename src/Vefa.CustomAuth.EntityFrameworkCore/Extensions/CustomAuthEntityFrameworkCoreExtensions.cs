using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.EntityFrameworkCore.Stores;

namespace Vefa.CustomAuth.EntityFrameworkCore.Extensions;

/// <summary>
/// Registers EF Core persistence services for Vefa.CustomAuth.
/// </summary>
public static class CustomAuthEntityFrameworkCoreExtensions
{
    /// <summary>
    /// Registers <see cref="CustomAuthDbContext"/> and the EF-backed store implementations.
    /// </summary>
    public static IServiceCollection AddVefaCustomAuthEntityFrameworkCore(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> optionsAction)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(optionsAction);

        services.AddDbContext<CustomAuthDbContext>(optionsAction);
        return services.AddVefaCustomAuthStores<CustomAuthDbContext>();
    }

    /// <summary>
    /// Registers EF-backed store implementations using the specified DbContext type.
    /// The context must include the Vefa.CustomAuth model configuration.
    /// </summary>
    public static IServiceCollection AddVefaCustomAuthStores<TContext>(this IServiceCollection services)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<ICustomAuthClientStore, EfCustomAuthClientStore<TContext>>();
        services.TryAddScoped<ICustomAuthAuthorizationCodeStore, EfCustomAuthAuthorizationCodeStore<TContext>>();
        services.TryAddScoped<ICustomAuthRefreshTokenStore, EfCustomAuthRefreshTokenStore<TContext>>();
        services.TryAddScoped<ICustomAuthSessionStore, EfCustomAuthSessionStore<TContext>>();
        services.TryAddScoped<ICustomAuthSigningKeyStore, EfCustomAuthSigningKeyStore<TContext>>();
        services.TryAddScoped<ICustomAuthScopeStore, EfCustomAuthScopeStore<TContext>>();
        services.TryAddScoped<ICustomAuthAuditLogStore, EfCustomAuthAuditLogStore<TContext>>();
        services.TryAddScoped<Core.Services.ICustomAuthCleanupService, Services.EfCustomAuthCleanupService<TContext>>();

        return services;
    }
}
