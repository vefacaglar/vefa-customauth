using System;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using global::MongoDB.Bson;
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
    public async Task<CustomAuthPagedResult<CustomAuthRefreshToken>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var filter = Builders<CustomAuthRefreshToken>.Filter.Empty;
        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var regex = new BsonRegularExpression(Regex.Escape(request.Search), "i");
            filter = Builders<CustomAuthRefreshToken>.Filter.Regex(t => t.ClientId, regex)
                | Builders<CustomAuthRefreshToken>.Filter.Regex(t => t.UserId, regex);
        }

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var totalCount = (int)await _collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken).ConfigureAwait(false);
        var items = await _collection.Find(filter)
            .SortByDescending(t => t.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthRefreshToken> { Items = items, TotalCount = totalCount };
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

    /// <inheritdoc/>
    public async Task RevokeBySessionIdAsync(Guid sessionId, DateTimeOffset revokedAt, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthRefreshToken>.Filter.Eq(t => t.SessionId, sessionId)
            & Builders<CustomAuthRefreshToken>.Filter.Eq(t => t.RevokedAt, null);
        var update = Builders<CustomAuthRefreshToken>.Update.Set(t => t.RevokedAt, revokedAt);
        await _collection.UpdateManyAsync(filter, update, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
