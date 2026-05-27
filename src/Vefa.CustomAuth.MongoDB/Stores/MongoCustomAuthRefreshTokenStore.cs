using System;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Stores;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthRefreshTokenStore"/>.
/// </summary>
public sealed class MongoCustomAuthRefreshTokenStore : ICustomAuthRefreshTokenStore
{
    private readonly IMongoCollection<CustomAuthRefreshToken> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthRefreshTokenStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthRefreshTokenStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthRefreshToken>(options.Value.RefreshTokensCollectionName);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthRefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        await _collection.InsertOneAsync(token, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthRefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(tokenHash);
        var filter = Builders<CustomAuthRefreshToken>.Filter.Eq(t => t.TokenHash, tokenHash);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthRefreshToken>.Filter.Eq(t => t.Id, id);
        var update = Builders<CustomAuthRefreshToken>.Update.Set(t => t.ConsumedAt, consumedAt);
        await _collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task RevokeAsync(Guid id, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthRefreshToken>.Filter.Eq(t => t.Id, id);
        var update = Builders<CustomAuthRefreshToken>.Update.Set(t => t.RevokedAt, revokedAt);
        await _collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
