using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Vefa.CustomAuth.AspNetCore.Stores.InMemory;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;

namespace Vefa.CustomAuth.AspNetCore.Extensions;

public sealed class InMemoryStoresBuilder
{
    public List<CustomAuthClient> Clients { get; } = new();
    public List<InMemoryUserStore.SeedUser> Users { get; } = new();
}

public static class InMemoryStoresExtensions
{
    /// <summary>
    /// Registers the in-memory store implementations as singletons.
    /// Optionally seeds clients and users via the configuration callback.
    /// Intended for samples, integration tests, and the v0.1 milestone only.
    /// </summary>
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

        return builder;
    }
}
