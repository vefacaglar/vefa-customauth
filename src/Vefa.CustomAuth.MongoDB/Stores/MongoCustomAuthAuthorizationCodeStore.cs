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
/// MongoDB implementation of <see cref="ICustomAuthAuthorizationCodeStore"/>.
/// </summary>
public sealed class MongoCustomAuthAuthorizationCodeStore : ICustomAuthAuthorizationCodeStore
{
    private readonly IMongoCollection<CustomAuthAuthorizationCode> _collection;

    /// <summary>
    /// Initializes a new instance of the <see cref="MongoCustomAuthAuthorizationCodeStore"/> class.
    /// </summary>
    /// <param name="database">The MongoDB database.</param>
    /// <param name="options">The MongoDB options.</param>
    public MongoCustomAuthAuthorizationCodeStore(IMongoDatabase database, IOptions<CustomAuthMongoDbOptions> options)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);
        _collection = database.GetCollection<CustomAuthAuthorizationCode>(options.Value.AuthorizationCodesCollectionName);
    }

    /// <inheritdoc/>
    public async Task StoreAsync(CustomAuthAuthorizationCode code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        await _collection.InsertOneAsync(code, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task<CustomAuthAuthorizationCode?> FindByHashAsync(string codeHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(codeHash);
        var filter = Builders<CustomAuthAuthorizationCode>.Filter.Eq(c => c.CodeHash, codeHash);
        return await _collection.Find(filter).FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task MarkConsumedAsync(Guid id, DateTimeOffset consumedAt, CancellationToken cancellationToken = default)
    {
        var filter = Builders<CustomAuthAuthorizationCode>.Filter.Eq(c => c.Id, id);
        var update = Builders<CustomAuthAuthorizationCode>.Update.Set(c => c.ConsumedAt, consumedAt);
        await _collection.UpdateOneAsync(filter, update, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
