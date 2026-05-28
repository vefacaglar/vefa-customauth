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
/// MongoDB implementation of <see cref="ICustomAuthClientStore"/>.
/// </summary>
public sealed class MongoCustomAuthClientStore : ICustomAuthClientStore
{
    private readonly IMongoCollection<CustomAuthClient> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthClientStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthClientStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthClient>(options.Value.ClientsCollectionName);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthClient?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        var filter = Builders<CustomAuthClient>.Filter.Eq(c => c.ClientId, clientId);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthPagedResult<CustomAuthClient>> GetPagedAsync(CustomAuthPagedRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var filter = Builders<CustomAuthClient>.Filter.Empty;
        if (!string.IsNullOrWhiteSpace(request.Search))
        {
            var pattern = Regex.Escape(request.Search);
            var regex = new BsonRegularExpression(pattern, "i");
            filter = Builders<CustomAuthClient>.Filter.Regex(c => c.ClientId, regex)
                | Builders<CustomAuthClient>.Filter.Regex(c => c.DisplayName, regex);
        }

        var page = request.Page > 0 ? request.Page : 1;
        var pageSize = request.PageSize > 0 ? request.PageSize : 10;

        var totalCount = (int)await _collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken).ConfigureAwait(false);
        var items = await _collection.Find(filter)
            .SortBy(c => c.ClientId)
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new CustomAuthPagedResult<CustomAuthClient> { Items = items, TotalCount = totalCount };
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(client.ClientId);

        var filter = Builders<CustomAuthClient>.Filter.Eq(c => c.ClientId, client.ClientId);
        await _collection.ReplaceOneAsync(filter, client, new ReplaceOptions { IsUpsert = true }, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(string clientId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        var filter = Builders<CustomAuthClient>.Filter.Eq(c => c.ClientId, clientId);
        await _collection.DeleteOneAsync(filter, cancellationToken).ConfigureAwait(false);
    }
}
