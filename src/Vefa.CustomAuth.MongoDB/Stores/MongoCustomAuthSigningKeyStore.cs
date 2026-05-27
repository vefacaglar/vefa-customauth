using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MongoDB.Driver;
using Vefa.CustomAuth.Core.Models;
using Vefa.CustomAuth.Core.Stores;
using Vefa.CustomAuth.MongoDB.Options;
using Microsoft.Extensions.Options;

namespace Vefa.CustomAuth.MongoDB.Stores;

/// <summary>
/// MongoDB implementation of <see cref="ICustomAuthSigningKeyStore"/>.
/// </summary>
public sealed class MongoCustomAuthSigningKeyStore : ICustomAuthSigningKeyStore
{
    private readonly IMongoCollection<CustomAuthSigningKey> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthSigningKeyStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthSigningKeyStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthSigningKey>(options.Value.SigningKeysCollectionName);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthSigningKey?> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthSigningKey>.Filter.Eq(k => k.IsActive, true)
            & Builders<CustomAuthSigningKey>.Filter.Eq(k => k.RetiredAt, null);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyList<CustomAuthSigningKey>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var keys = await _collection.Find(Builders<CustomAuthSigningKey>.Filter.Empty)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return keys.OrderByDescending(k => k.CreatedAt).ToList();
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthSigningKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        await _collection.InsertOneAsync(key, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
