using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Services;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Vefa.CustomAuth.MongoDB.Services;
using Vefa.CustomAuth.MongoDB.Stores;

namespace Vefa.CustomAuth.MongoDB.Extensions;

/// <summary>
/// Extension methods for registering MongoDB-backed CustomAuth stores.
/// </summary>
public static class CustomAuthMongoDbExtensions
{
    /// <summary>
    /// Registers MongoDB-backed CustomAuth stores using the specified options.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">An action to configure <see cref="CustomAuthMongoDbOptions"/>.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddVefaCustomAuthMongoDbStores(
        this IServiceCollection services,
        Action<CustomAuthMongoDbOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        var mongoOptions = new CustomAuthMongoDbOptions();
        configure(mongoOptions);
        ValidateOptions(mongoOptions);

        MongoCustomAuthClassMap.Register();

        var client = new MongoClient(mongoOptions.ConnectionString);
        services.TryAddSingleton<IMongoClient>(client);
        services.TryAddSingleton<IMongoDatabase>(client.GetDatabase(mongoOptions.DatabaseName));

        services.TryAddScoped<ICustomAuthClientStore, MongoCustomAuthClientStore>();
        services.TryAddScoped<ICustomAuthAuthorizationCodeStore, MongoCustomAuthAuthorizationCodeStore>();
        services.TryAddScoped<ICustomAuthRefreshTokenStore, MongoCustomAuthRefreshTokenStore>();
        services.TryAddScoped<ICustomAuthSessionStore, MongoCustomAuthSessionStore>();
        services.TryAddScoped<ICustomAuthSigningKeyStore, MongoCustomAuthSigningKeyStore>();
        services.TryAddScoped<ICustomAuthScopeStore, MongoCustomAuthScopeStore>();
        services.TryAddScoped<ICustomAuthAuditLogStore, MongoCustomAuthAuditLogStore>();
        services.TryAddScoped<ICustomAuthCleanupService, MongoCustomAuthCleanupService>();

        return services;
    }

    private static void ValidateOptions(CustomAuthMongoDbOptions options)
    {
        ArgumentException.ThrowIfNullOrEmpty(options.ConnectionString);
        ArgumentException.ThrowIfNullOrEmpty(options.DatabaseName);
        ArgumentException.ThrowIfNullOrEmpty(options.ClientsCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.AuthorizationCodesCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.RefreshTokensCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.SessionsCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.SigningKeysCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.ScopesCollectionName);
        ArgumentException.ThrowIfNullOrEmpty(options.AuditLogsCollectionName);
    }
}
