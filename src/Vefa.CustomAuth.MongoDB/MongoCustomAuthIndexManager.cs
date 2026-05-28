using System;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.MongoDB.Options;

namespace Vefa.CustomAuth.MongoDB;

/// <summary>
/// Provides methods to create MongoDB indexes for CustomAuth collections.
/// </summary>
public static class MongoCustomAuthIndexManager
{
    /// <summary>
    /// Creates all required indexes for CustomAuth collections.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public static async Task EnsureIndexesAsync(
        IMongoDatabase database,
        CustomAuthMongoDbOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);

        await EnsureAuthorizationCodeIndexesAsync(database, options, cancellationToken).ConfigureAwait(false);
        await EnsureRefreshTokenIndexesAsync(database, options, cancellationToken).ConfigureAwait(false);
        await EnsureSessionIndexesAsync(database, options, cancellationToken).ConfigureAwait(false);
        await EnsureAuditLogIndexesAsync(database, options, cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureAuthorizationCodeIndexesAsync(
        IMongoDatabase database,
        CustomAuthMongoDbOptions options,
        CancellationToken cancellationToken)
    {
        var collection = database.GetCollection<CustomAuthAuthorizationCode>(options.AuthorizationCodesCollectionName);
        var indexModels = new CreateIndexModel<CustomAuthAuthorizationCode>[]
        {
            new(Builders<CustomAuthAuthorizationCode>.IndexKeys.Ascending(c => c.CodeHash),
                new CreateIndexOptions { Unique = true, Name = "IX_CodeHash" }),
            new(Builders<CustomAuthAuthorizationCode>.IndexKeys.Ascending(c => c.ClientId),
                new CreateIndexOptions { Name = "IX_ClientId" }),
            new(Builders<CustomAuthAuthorizationCode>.IndexKeys.Ascending(c => c.UserId),
                new CreateIndexOptions { Name = "IX_UserId" }),
            new(Builders<CustomAuthAuthorizationCode>.IndexKeys.Ascending(c => c.ExpiresAt),
                new CreateIndexOptions { Name = "IX_ExpiresAt" }),
        };
        await collection.Indexes.CreateManyAsync(indexModels, cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureRefreshTokenIndexesAsync(
        IMongoDatabase database,
        CustomAuthMongoDbOptions options,
        CancellationToken cancellationToken)
    {
        var collection = database.GetCollection<CustomAuthRefreshToken>(options.RefreshTokensCollectionName);
        var indexModels = new CreateIndexModel<CustomAuthRefreshToken>[]
        {
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.TokenHash),
                new CreateIndexOptions { Unique = true, Name = "IX_TokenHash" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.ClientId),
                new CreateIndexOptions { Name = "IX_ClientId" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.UserId),
                new CreateIndexOptions { Name = "IX_UserId" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.SessionId),
                new CreateIndexOptions { Name = "IX_SessionId" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.ParentTokenId),
                new CreateIndexOptions { Name = "IX_ParentTokenId" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.ExpiresAt),
                new CreateIndexOptions { Name = "IX_ExpiresAt" }),
            new(Builders<CustomAuthRefreshToken>.IndexKeys.Ascending(t => t.AbsoluteExpiresAt),
                new CreateIndexOptions { Name = "IX_AbsoluteExpiresAt" }),
        };
        await collection.Indexes.CreateManyAsync(indexModels, cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureSessionIndexesAsync(
        IMongoDatabase database,
        CustomAuthMongoDbOptions options,
        CancellationToken cancellationToken)
    {
        var collection = database.GetCollection<CustomAuthSession>(options.SessionsCollectionName);
        var indexModels = new CreateIndexModel<CustomAuthSession>[]
        {
            new(Builders<CustomAuthSession>.IndexKeys.Ascending(s => s.UserId),
                new CreateIndexOptions { Name = "IX_UserId" }),
            new(Builders<CustomAuthSession>.IndexKeys.Ascending(s => s.ExpiresAt),
                new CreateIndexOptions { Name = "IX_ExpiresAt" }),
        };
        await collection.Indexes.CreateManyAsync(indexModels, cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureAuditLogIndexesAsync(
        IMongoDatabase database,
        CustomAuthMongoDbOptions options,
        CancellationToken cancellationToken)
    {
        var collection = database.GetCollection<CustomAuthAuditLog>(options.AuditLogsCollectionName);
        var indexModels = new CreateIndexModel<CustomAuthAuditLog>[]
        {
            new(Builders<CustomAuthAuditLog>.IndexKeys.Descending(l => l.Timestamp),
                new CreateIndexOptions { Name = "IX_Timestamp" }),
            new(Builders<CustomAuthAuditLog>.IndexKeys.Ascending(l => l.ActorUserId),
                new CreateIndexOptions { Name = "IX_ActorUserId" }),
            new(Builders<CustomAuthAuditLog>.IndexKeys.Combine(
                    Builders<CustomAuthAuditLog>.IndexKeys.Ascending(l => l.TargetType),
                    Builders<CustomAuthAuditLog>.IndexKeys.Ascending(l => l.TargetId)),
                new CreateIndexOptions { Name = "IX_TargetType_TargetId" }),
        };
        await collection.Indexes.CreateManyAsync(indexModels, cancellationToken).ConfigureAwait(false);
    }
}
